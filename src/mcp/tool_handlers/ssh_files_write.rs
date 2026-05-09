//! SSH Multi-File Write Tool Handler
//!
//! Writes or uploads multiple files to a remote host in a single SFTP session.
//! Each file entry can provide inline `content` or a `local_path` to upload.

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
use crate::ssh::DEFAULT_CHUNK_SIZE;

use super::utils::{connect_with_jump, validate_path};

#[derive(Debug, Deserialize)]
struct SshFilesWriteArgs {
    host: String,
    files: Vec<FileEntry>,
    #[serde(default)]
    stop_on_error: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FileEntry {
    remote_path: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    local_path: Option<String>,
    #[serde(default)]
    append: Option<bool>,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "host": {
            "type": "string",
            "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
        },
        "files": {
            "type": "array",
            "description": "Array of files to write or upload. Each entry needs a remote_path plus either content (inline) or local_path (upload from local disk).",
            "items": {
                "type": "object",
                "properties": {
                    "remote_path": {
                        "type": "string",
                        "description": "Destination path on the remote host"
                    },
                    "content": {
                        "type": "string",
                        "description": "Inline content to write (mutually exclusive with local_path)"
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Local file to upload (mutually exclusive with content)"
                    },
                    "append": {
                        "type": "boolean",
                        "default": false,
                        "description": "Append instead of overwriting (only for inline content)"
                    }
                },
                "required": ["remote_path"]
            },
            "minItems": 1,
            "maxItems": 100
        },
        "stop_on_error": {
            "type": "boolean",
            "default": false,
            "description": "Stop processing remaining files on first error (default: false, continue all and report errors)"
        }
    },
    "required": ["host", "files"]
}"#;

/// Handler for the `ssh_files_write` tool.
///
/// Writes or uploads multiple files to a remote host in a single SFTP session.
/// Each file can provide inline `content` or a `local_path` to upload.
#[mcp_tool(
    name = "ssh_files_write",
    group = "file_ops",
    annotation = "destructive"
)]
pub struct SshFilesWriteHandler;

#[async_trait]
impl ToolHandler for SshFilesWriteHandler {
    fn name(&self) -> &'static str {
        "ssh_files_write"
    }

    fn description(&self) -> &'static str {
        "Write or upload multiple files to a remote host in a single call. Each file entry \
         provides a remote_path plus either inline content or a local_path to upload. All \
         files share one SFTP session for efficiency. By default continues on errors and \
         reports per-file results; set stop_on_error=true to fail fast."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        // Step 1: Parse args
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshFilesWriteArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if args.files.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "files array must not be empty".to_string(),
            ));
        }

        // Step 2: Validate all entries upfront
        for (i, entry) in args.files.iter().enumerate() {
            match (&entry.content, &entry.local_path) {
                (None, None) => {
                    return Err(BridgeError::McpInvalidRequest(format!(
                        "files[{i}]: must provide either 'content' or 'local_path'"
                    )));
                }
                (Some(_), Some(_)) => {
                    return Err(BridgeError::McpInvalidRequest(format!(
                        "files[{i}]: 'content' and 'local_path' are mutually exclusive"
                    )));
                }
                _ => {}
            }
            validate_path(&entry.remote_path)?;
            ctx.validate_root_scope(&entry.remote_path)?;
            if let Some(lp) = &entry.local_path {
                validate_path(lp)?;
                let expanded = crate::path_utils::home_expand_or_input(lp);
                if !Path::new(&expanded).exists() {
                    return Err(BridgeError::FileTransfer {
                        reason: format!("Local file not found: {lp}"),
                    });
                }
            }
        }

        // Step 3: Host config + rate limit
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        let stop_on_error = args.stop_on_error.unwrap_or(false);

        // Confirm destructive batch write via elicitation. Falls back
        // to a no-op when the client does not advertise the elicitation
        // capability — the global `require_elicitation_on_destructive`
        // gate still applies in that case.
        let summary = format!(
            "Write {} file(s) on host `{}` (stop_on_error={})",
            args.files.len(),
            args.host,
            stop_on_error,
        );
        if let Some(false) = ctx.elicit_confirm(self.name(), &summary).await? {
            return Ok(ToolCallResult::error(format!(
                "User declined batch write of {} files on `{}`",
                args.files.len(),
                args.host
            )));
        }

        info!(
            host = %args.host,
            file_count = args.files.len(),
            stop_on_error,
            "Writing multiple files via SFTP"
        );

        // Step 4: Connect + SFTP session
        let client =
            connect_with_jump(&args.host, host_config, &ctx.config.limits, &ctx.config).await?;
        let sftp = client.sftp_session().await?;

        // Step 5: Process each file. Per-entry `notifications/progress`
        // when the client supplied a progressToken — no-op otherwise.
        let progress = ctx.progress_reporter(Some(args.files.len() as u64));
        let mut output = String::new();
        let mut success_count: u32 = 0;
        let mut error_count: u32 = 0;
        let mut total_bytes: u64 = 0;

        for (i, entry) in args.files.iter().enumerate() {
            if let Some(reporter) = progress.as_ref() {
                reporter.report(
                    (i + 1) as u64,
                    Some(&format!(
                        "{} ({}/{})",
                        entry.remote_path,
                        i + 1,
                        args.files.len()
                    )),
                );
            }
            let result = if let Some(content) = &entry.content {
                let append = entry.append.unwrap_or(false);
                sftp.write_bytes(
                    content.as_bytes(),
                    &entry.remote_path,
                    append,
                    DEFAULT_CHUNK_SIZE,
                )
                .await
            } else if let Some(local_path) = &entry.local_path {
                let expanded = crate::path_utils::home_expand_or_input(local_path);
                let options = crate::ssh::TransferOptions::default();
                sftp.upload_file::<fn(crate::ssh::TransferProgress)>(
                    Path::new(&expanded),
                    &entry.remote_path,
                    &options,
                    None,
                )
                .await
            } else {
                return Err(BridgeError::McpInvalidRequest(format!(
                    "files[{i}]: missing both 'content' and 'local_path' (validation invariant violated)"
                )));
            };

            let action = if entry.content.is_some() {
                format!("SFTP_MULTI_WRITE {}", entry.remote_path)
            } else {
                format!(
                    "SFTP_MULTI_UPLOAD {} -> {}",
                    entry.local_path.as_deref().unwrap_or("?"),
                    entry.remote_path
                )
            };

            match result {
                Ok(tr) => {
                    ctx.audit_logger.log(AuditEvent::new(
                        &args.host,
                        &action,
                        AuditCommandResult::Success {
                            exit_code: 0,
                            duration_ms: tr.duration_ms,
                        },
                    ));
                    success_count += 1;
                    total_bytes += tr.bytes_transferred;
                    let _ = writeln!(
                        output,
                        "[{}/{}] OK  {} ({} bytes, {}ms)",
                        i + 1,
                        args.files.len(),
                        entry.remote_path,
                        tr.bytes_transferred,
                        tr.duration_ms
                    );
                }
                Err(e) => {
                    ctx.audit_logger.log(AuditEvent::new(
                        &args.host,
                        &action,
                        AuditCommandResult::Error {
                            message: e.to_string(),
                        },
                    ));
                    error_count += 1;
                    let _ = writeln!(
                        output,
                        "[{}/{}] ERR {} — {}",
                        i + 1,
                        args.files.len(),
                        entry.remote_path,
                        e
                    );
                    if stop_on_error {
                        let _ = writeln!(
                            output,
                            "Stopped after error (stop_on_error=true). {}/{} files remaining.",
                            args.files.len() - i - 1,
                            args.files.len()
                        );
                        break;
                    }
                }
            }
        }

        // Step 6: Close SFTP session
        sftp.close().await.ok();

        // Step 7: Summary
        let _ = writeln!(output, "---");
        let _ = writeln!(
            output,
            "Summary: {success_count} succeeded, {error_count} failed, {total_bytes} bytes total"
        );

        Ok(ToolCallResult::text(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFilesWriteHandler;
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
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "files": [{"remote_path": "/tmp/a", "content": "x"}]
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

    #[test]
    fn test_schema() {
        let handler = SshFilesWriteHandler;
        assert_eq!(handler.name(), "ssh_files_write");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_files_write");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("files")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "files": [
                {"remote_path": "/tmp/a.txt", "content": "hello"},
                {"remote_path": "/tmp/b.txt", "local_path": "/local/b.txt"},
                {"remote_path": "/tmp/c.txt", "content": "append", "append": true}
            ],
            "stop_on_error": true
        });
        let args: SshFilesWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.files.len(), 3);
        assert_eq!(args.stop_on_error, Some(true));
        assert!(args.files[0].content.is_some());
        assert!(args.files[1].local_path.is_some());
        assert_eq!(args.files[2].append, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "files": [{"remote_path": "/tmp/a", "content": "x"}]
        });
        let args: SshFilesWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.files.len(), 1);
        assert!(args.stop_on_error.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFilesWriteHandler;
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("stop_on_error"));
        assert!(properties.contains_key("files"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "s1",
            "files": [{"remote_path": "/tmp/a", "content": "x"}]
        });
        let args: SshFilesWriteArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFilesWriteArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_file_entry_requires_content_or_local_path() {
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "files": [{"remote_path": "/tmp/a"}]
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("content"));
                assert!(msg.contains("local_path"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_file_entry_rejects_both() {
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "files": [{"remote_path": "/tmp/a", "content": "x", "local_path": "/tmp/b"}]
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("mutually exclusive"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "files": [{"remote_path": "/tmp/../etc/passwd", "content": "x"}]
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains(".."));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_local_path_not_found() {
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "files": [{"remote_path": "/tmp/a", "local_path": "/nonexistent/file.txt"}]
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

    #[tokio::test]
    async fn test_empty_files_rejected() {
        let handler = SshFilesWriteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "files": []
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_description_mentions_sftp() {
        let handler = SshFilesWriteHandler;
        assert!(handler.description().contains("SFTP"));
    }
}
