//! SSH List Directory Tool Handler
//!
//! Lists files and directories on remote hosts via SFTP.

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

/// Arguments for `ssh_ls` tool
#[derive(Debug, Deserialize)]
struct SshLsArgs {
    host: String,
    path: String,
    #[serde(default)]
    recursive: Option<bool>,
    #[serde(default)]
    max_depth: Option<u32>,
    #[serde(default)]
    include_hidden: Option<bool>,
    #[serde(default)]
    sort_by: Option<String>,
}

/// SSH List Directory tool handler
#[mcp_tool(name = "ssh_ls", group = "directory", annotation = "read_only")]
pub struct SshLsHandler;

impl SshLsHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "path": {
                "type": "string",
                "description": "The remote directory path to list"
            },
            "recursive": {
                "type": "boolean",
                "default": false,
                "description": "Recursively list subdirectories"
            },
            "max_depth": {
                "type": "integer",
                "default": 10,
                "description": "Maximum depth for recursive listing (default: 10). Applies only when recursive=true. The default of 10 can produce very large output on deep trees — lower this or apply a jq_filter when recursing large directories."
            },
            "include_hidden": {
                "type": "boolean",
                "default": false,
                "description": "Include hidden files (names starting with '.')"
            },
            "sort_by": {
                "type": "string",
                "enum": ["name", "size", "type"],
                "default": "name",
                "description": "Sort entries by: name (default), size, or type"
            }
        },
        "required": ["host", "path"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshLsHandler {
    fn name(&self) -> &'static str {
        "ssh_ls"
    }

    fn description(&self) -> &'static str {
        "List files and directories on a remote host via SFTP. Prefer this over ssh_exec \
         as it returns structured JSON entries with name, size, type, permissions, and \
         modified timestamp via native SFTP (not shell) — works even when the remote shell \
         is restricted or unavailable (e.g. rssh/scponly setups) and avoids shell injection \
         risks. Supports recursive listing with configurable depth. For searching files by \
         name pattern, use ssh_find. For reading file contents, use ssh_tail or ssh_download \
         instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::Json
    }

    #[expect(clippy::too_many_lines, clippy::cast_possible_truncation)]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(mut v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let args: SshLsArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Validate path for traversal attacks
        validate_path(&args.path)?;

        // Validate path is within declared workspace roots
        ctx.validate_root_scope(&args.path)?;

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

        let recursive = args.recursive.unwrap_or(false);
        let max_depth = args.max_depth.unwrap_or(10);
        let include_hidden = args.include_hidden.unwrap_or(false);
        let sort_by = args.sort_by.as_deref().unwrap_or("name");

        info!(
            host = %args.host,
            path = %args.path,
            recursive = recursive,
            max_depth = max_depth,
            include_hidden = include_hidden,
            sort_by = sort_by,
            "Listing directory via SFTP"
        );

        let start = std::time::Instant::now();

        // Connect to host (via jump host if configured)
        let client =
            connect_with_jump(&args.host, host_config, &ctx.config.limits, &ctx.config).await?;

        // Create SFTP session
        let sftp = client.sftp_session().await?;

        // Collect directory entries
        let result = if recursive {
            // Walk directory tree using a stack
            let mut all_entries = Vec::new();
            // Stack of (path, depth)
            let mut stack: Vec<(String, u32)> = vec![(args.path.clone(), 0)];

            while let Some((dir_path, depth)) = stack.pop() {
                match sftp.read_dir(&dir_path).await {
                    Ok(entries) => {
                        for entry in entries {
                            all_entries.push(entry.clone());
                            if entry.is_dir && depth < max_depth {
                                stack.push((entry.path.clone(), depth + 1));
                            }
                        }
                    }
                    Err(e) => {
                        // Log error but continue with other directories
                        tracing::warn!(
                            path = %dir_path,
                            error = %e,
                            "Failed to read directory during recursive listing"
                        );
                    }
                }
            }

            Ok(all_entries)
        } else {
            sftp.read_dir(&args.path).await
        };

        // Close SFTP session
        sftp.close().await.ok();

        let duration_ms = start.elapsed().as_millis() as u64;

        // Log the result
        match &result {
            Ok(entries) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("SFTP_LS {}", args.path),
                    AuditCommandResult::Success {
                        exit_code: 0,
                        duration_ms,
                    },
                ));

                let mut entries = entries.clone();

                // Filter hidden files if not included
                if !include_hidden {
                    entries.retain(|e| !e.name.starts_with('.'));
                }

                // Sort entries
                match sort_by {
                    "size" => entries.sort_by(|a, b| a.size.cmp(&b.size)),
                    "type" => {
                        entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
                    }
                    // "name" or default
                    _ => entries.sort_by(|a, b| a.name.cmp(&b.name)),
                }

                let mut json_output =
                    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());

                crate::mcp::standard_tool::apply_reduction(
                    &mut json_output,
                    &dr,
                    crate::domain::output_kind::OutputKind::Json,
                )?;

                Ok(ToolCallResult::text(json_output))
            }
            Err(e) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("SFTP_LS {}", args.path),
                    AuditCommandResult::Error {
                        message: e.to_string(),
                    },
                ));

                Err(BridgeError::Sftp {
                    reason: e.to_string(),
                })
            }
        }
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
        let handler = SshLsHandler;
        assert_eq!(handler.name(), "ssh_ls");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ls");

        // Validate JSON is well-formed
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLsHandler;
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
        let handler = SshLsHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "path": "/home/user"
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
        let handler = SshLsHandler;
        let ctx = create_test_context();

        // Missing required field "path"
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshLsHandler;
        assert!(handler.description().contains("List"));
        assert!(handler.description().contains("SFTP"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLsHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("recursive"));
        assert!(properties.contains_key("max_depth"));
        assert!(properties.contains_key("include_hidden"));
        assert!(properties.contains_key("sort_by"));
    }

    // Note: ssh_ls uses SFTP directly (not SSH exec), so it cannot be tested
    // with the mock executor infrastructure. The mock executor only stubs
    // command execution, not SFTP sessions.
}
