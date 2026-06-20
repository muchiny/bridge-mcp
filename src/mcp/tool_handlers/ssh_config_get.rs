//! SSH Config Get Tool Handler
//!
//! Returns the current effective configuration limits.

use std::fmt::Write;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Handler for `ssh_config_get`
#[mcp_tool(name = "ssh_config_get", group = "config", annotation = "read_only")]
pub struct SshConfigGetHandler;

impl SshConfigGetHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "Config key to retrieve. Omit this parameter entirely to get all limit values as an object.",
                "enum": ["max_output_chars", "command_timeout_seconds", "max_concurrent_commands"]
            }
        },
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshConfigGetHandler {
    fn name(&self) -> &'static str {
        "ssh_config_get"
    }

    fn description(&self) -> &'static str {
        "Bridge-local: reads the current effective configuration limits of the MCP bridge \
         session itself — not a remote host (there is no host param). Returns \
         max_output_chars, command_timeout_seconds, max_concurrent_commands, and other \
         session-level limits. Use ssh_config_set to change max_output_chars at runtime. \
         Useful to check your output budget before running commands that produce large output."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let key = args
            .and_then(|v| v.get("key").and_then(|k| k.as_str().map(String::from)))
            .unwrap_or_else(|| "all".to_string());

        let limits = &ctx.config.limits;
        let mut result = String::new();

        match key.as_str() {
            "max_output_chars" => {
                let _ = writeln!(result, "max_output_chars: {}", limits.max_output_chars);
            }
            "command_timeout_seconds" => {
                let _ = writeln!(
                    result,
                    "command_timeout_seconds: {}",
                    limits.command_timeout_seconds
                );
            }
            "max_concurrent_commands" => {
                let _ = writeln!(
                    result,
                    "max_concurrent_commands: {}",
                    limits.max_concurrent_commands
                );
            }
            _ => {
                let _ = writeln!(result, "Current effective limits:");
                let _ = writeln!(result, "  max_output_chars: {}", limits.max_output_chars);
                let _ = writeln!(
                    result,
                    "  command_timeout_seconds: {}",
                    limits.command_timeout_seconds
                );
                let _ = writeln!(result, "  max_output_bytes: {}", limits.max_output_bytes);
                let _ = writeln!(
                    result,
                    "  max_concurrent_commands: {}",
                    limits.max_concurrent_commands
                );
                let _ = writeln!(
                    result,
                    "  connection_timeout_seconds: {}",
                    limits.connection_timeout_seconds
                );
                let _ = writeln!(
                    result,
                    "  rate_limit_per_second: {}",
                    limits.rate_limit_per_second
                );
                let _ = writeln!(
                    result,
                    "  output_cache_ttl_seconds: {}",
                    limits.output_cache_ttl_seconds
                );
                let _ = writeln!(
                    result,
                    "  output_cache_max_entries: {}",
                    limits.output_cache_max_entries
                );
                let _ = writeln!(
                    result,
                    "  sftp_write_threshold_bytes: {}",
                    limits.sftp_write_threshold_bytes
                );
            }
        }

        Ok(ToolCallResult::text(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context;

    fn get_text_content(result: &ToolCallResult) -> &str {
        match &result.content[0] {
            ToolContent::Text { text } => text,
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_config_get_all() {
        let handler = SshConfigGetHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("max_output_chars: 40000"));
        assert!(text.contains("command_timeout_seconds:"));
        assert!(text.contains("max_concurrent_commands:"));
    }

    #[tokio::test]
    async fn test_config_get_specific_key() {
        let handler = SshConfigGetHandler;
        let ctx = create_test_context();

        let args = serde_json::json!({"key": "max_output_chars"});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("max_output_chars: 40000"));
        assert!(!text.contains("command_timeout_seconds"));
    }

    #[test]
    fn test_schema() {
        let handler = SshConfigGetHandler;
        assert_eq!(handler.name(), "ssh_config_get");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_config_get");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }
}
