//! SSH Upload Tool Handler
//!
//! Uploads files to remote hosts via SFTP.

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
use crate::ssh::{DEFAULT_CHUNK_SIZE, TransferMode, TransferOptions, TransferProgress};

use super::utils::{connect_with_jump, validate_path};

/// Arguments for `ssh_upload` tool
#[derive(Debug, Deserialize)]
struct SshUploadArgs {
    host: String,
    local_path: String,
    remote_path: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    chunk_size: Option<u64>,
    #[serde(default)]
    verify_checksum: Option<bool>,
    #[serde(default)]
    preserve_permissions: Option<bool>,
}

/// SSH Upload tool handler
#[mcp_tool(name = "ssh_upload", group = "file_transfer", annotation = "mutating")]
pub struct SshUploadHandler;

impl SshUploadHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "local_path": {
                "type": "string",
                "description": "Path to the local file to upload"
            },
            "remote_path": {
                "type": "string",
                "description": "Destination path on the remote host"
            },
            "mode": {
                "type": "string",
                "enum": ["overwrite", "append", "resume", "fail_if_exists"],
                "default": "overwrite",
                "description": "Transfer mode: overwrite (default), append, resume, or fail_if_exists"
            },
            "chunk_size": {
                "type": "integer",
                "default": 1048576,
                "description": "Chunk size in bytes for streaming (default: 1MB)"
            },
            "verify_checksum": {
                "type": "boolean",
                "default": false,
                "description": "Verify SHA256 checksum after transfer"
            },
            "preserve_permissions": {
                "type": "boolean",
                "default": true,
                "description": "Preserve file permissions"
            }
        },
        "required": ["host", "local_path", "remote_path"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshUploadHandler {
    fn name(&self) -> &'static str {
        "ssh_upload"
    }

    fn description(&self) -> &'static str {
        "Upload a single file to a remote host via SFTP. Streaming transfer with no size \
         limit, optional SHA256 checksum verification, and resume support. For uploading \
         entire directories, use ssh_sync with direction 'upload' instead. Returns transfer \
         confirmation with bytes transferred."
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
        let args: SshUploadArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Validate paths for traversal attacks
        validate_path(&args.local_path)?;
        validate_path(&args.remote_path)?;
        ctx.validate_root_scope(&args.remote_path)?;

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        // Parse transfer mode
        let mode_str = args.mode.as_deref().unwrap_or("overwrite");
        let transfer_mode =
            TransferMode::parse(mode_str).ok_or_else(|| BridgeError::FileTransfer {
                reason: format!(
                    "Invalid transfer mode: {mode_str}. Valid modes: overwrite, append, resume, fail_if_exists"
                ),
            })?;

        // Expand local path (`~` -> home dir; non-tilde inputs are passed through).
        let local_path = crate::path_utils::home_expand_or_input(&args.local_path);
        let local_path = Path::new(&local_path);

        // Check local file exists
        if !local_path.exists() {
            return Err(BridgeError::FileTransfer {
                reason: format!("Local file not found: {}", args.local_path),
            });
        }

        let metadata = std::fs::metadata(local_path).map_err(|e| BridgeError::FileTransfer {
            reason: format!("Cannot read file metadata: {e}"),
        })?;

        info!(
            host = %args.host,
            local = %args.local_path,
            remote = %args.remote_path,
            size = metadata.len(),
            mode = %mode_str,
            "Uploading file via SFTP"
        );

        // Build transfer options
        let options = TransferOptions {
            mode: transfer_mode,
            chunk_size: args.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
            verify_checksum: args.verify_checksum.unwrap_or(false),
            preserve_permissions: args.preserve_permissions.unwrap_or(true),
        };

        // Connect to host (via jump host if configured)
        let client =
            connect_with_jump(&args.host, host_config, &ctx.config.limits, &ctx.config).await?;

        // Create SFTP session
        let sftp = client.sftp_session().await?;

        // Upload the file (no progress callback for MCP)
        let result = sftp
            .upload_file::<fn(TransferProgress)>(local_path, &args.remote_path, &options, None)
            .await;

        // Log the result
        match &result {
            Ok(transfer_result) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("SFTP_UPLOAD {} -> {}", args.local_path, args.remote_path),
                    AuditCommandResult::Success {
                        exit_code: 0,
                        duration_ms: transfer_result.duration_ms,
                    },
                ));
            }
            Err(e) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("SFTP_UPLOAD {} -> {}", args.local_path, args.remote_path),
                    AuditCommandResult::Error {
                        message: e.to_string(),
                    },
                ));
            }
        }

        let transfer_result = result?;

        // Format output
        let mut output = String::new();
        let _ = writeln!(output, "File uploaded successfully:");
        let _ = writeln!(output, "  Host: {}", args.host);
        let _ = writeln!(output, "  Local: {}", args.local_path);
        let _ = writeln!(output, "  Remote: {}", args.remote_path);
        let _ = writeln!(
            output,
            "  Size: {} bytes",
            transfer_result.bytes_transferred
        );
        let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
        let _ = writeln!(
            output,
            "  Speed: {:.2} MB/s",
            transfer_result.bytes_per_second / 1_000_000.0
        );
        if let Some(checksum) = &transfer_result.checksum {
            let _ = writeln!(output, "  SHA256: {checksum}");
        }

        Ok(ToolCallResult::text(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUploadHandler;
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
    async fn test_invalid_arguments() {
        let handler = SshUploadHandler;
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
    async fn test_unknown_host() {
        let handler = SshUploadHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "local_path": "/tmp/test.txt",
                    "remote_path": "/home/user/test.txt"
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
    async fn test_file_not_found() {
        let handler = SshUploadHandler;
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "local_path": "/nonexistent/path/file.txt",
                    "remote_path": "/home/user/file.txt"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("not found"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshUploadHandler;
        assert_eq!(handler.name(), "ssh_upload");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_upload");
    }

    #[test]
    fn test_schema_required_fields() {
        let handler = SshUploadHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("local_path")));
        assert!(required.contains(&json!("remote_path")));
    }

    #[test]
    fn test_schema_transfer_modes() {
        let handler = SshUploadHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let mode_enum = schema_json["properties"]["mode"]["enum"]
            .as_array()
            .unwrap();
        assert!(mode_enum.contains(&json!("overwrite")));
        assert!(mode_enum.contains(&json!("append")));
        assert!(mode_enum.contains(&json!("resume")));
        assert!(mode_enum.contains(&json!("fail_if_exists")));
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshUploadHandler;
        assert!(handler.description().contains("Upload"));
        assert!(handler.description().contains("SFTP"));
    }
}
