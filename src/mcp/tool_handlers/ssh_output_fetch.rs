//! SSH Output Fetch Tool Handler
//!
//! Retrieves full or paginated output from a previous truncated tool call
//! using the output cache.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_output_fetch` tool
#[derive(Debug, Deserialize)]
struct SshOutputFetchArgs {
    output_id: String,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    limit: Option<u64>,
}

/// SSH Output Fetch tool handler
#[mcp_tool(name = "ssh_output_fetch", group = "core", annotation = "read_only")]
pub struct SshOutputFetchHandler;

impl SshOutputFetchHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "output_id": {
                "type": "string",
                "description": "The output ID from a previous truncated tool response (e.g., 'out-0042')"
            },
            "offset": {
                "type": "integer",
                "description": "Character offset to start from (default: 0)",
                "minimum": 0,
                "default": 0
            },
            "limit": {
                "type": "integer",
                "description": "Maximum characters to return in this page (default: server config max_output_chars, typically 20000). Use with offset to paginate: increment offset by the chars returned each call until has_more=false in the response header.",
                "minimum": 1
            }
        },
        "required": ["output_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshOutputFetchHandler {
    fn name(&self) -> &'static str {
        "ssh_output_fetch"
    }

    fn description(&self) -> &'static str {
        "Retrieve full or paginated output from a previous truncated tool call. \
         Use the output_id shown in the truncation message (e.g., 'out-0042'). \
         Supports offset/limit for pagination through large outputs."
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
        let args: SshOutputFetchArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let Some(ref cache) = ctx.output_cache else {
            return Ok(ToolCallResult::error(
                "Output cache is not available. This tool is only supported in MCP server mode."
                    .to_string(),
            ));
        };

        #[allow(clippy::cast_possible_truncation)]
        let offset = args.offset.unwrap_or(0) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let limit = args
            .limit
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);

        let Some(result) = cache.fetch(&args.output_id, offset, limit).await else {
            return Ok(ToolCallResult::error(format!(
                "Output '{}' not found. It may have expired (TTL: {}s) or been evicted.",
                args.output_id, ctx.config.limits.output_cache_ttl_seconds
            )));
        };

        let header = format!(
            "--- output_id={} | offset={} | chars={}/{} | has_more={} ---\n",
            args.output_id,
            result.offset,
            result.text.len(),
            result.total_chars,
            result.has_more
        );

        Ok(ToolCallResult::text(format!("{header}{}", result.text)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OutputCache;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context;
    use serde_json::json;
    use std::sync::Arc;

    fn get_text_content(result: &ToolCallResult) -> &str {
        match &result.content[0] {
            ToolContent::Text { text } => text,
            _ => panic!("Expected Text content"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshOutputFetchHandler;
        assert_eq!(handler.name(), "ssh_output_fetch");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_output_fetch");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("output_id")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshOutputFetchHandler;
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
    async fn test_no_cache_returns_error() {
        let handler = SshOutputFetchHandler;
        let ctx = create_test_context(); // output_cache is None

        let result = handler
            .execute(Some(json!({"output_id": "out-0000"})), &ctx)
            .await
            .unwrap();

        assert!(result.is_error.unwrap_or(false));
        assert!(get_text_content(&result).contains("not available"));
    }

    #[tokio::test]
    async fn test_fetch_nonexistent_id() {
        let handler = SshOutputFetchHandler;
        let mut ctx = create_test_context();
        ctx.output_cache = Some(Arc::new(OutputCache::new(300, 100)));

        let result = handler
            .execute(Some(json!({"output_id": "out-9999"})), &ctx)
            .await
            .unwrap();

        assert!(result.is_error.unwrap_or(false));
        assert!(get_text_content(&result).contains("not found"));
    }

    #[tokio::test]
    async fn test_fetch_stored_output() {
        let handler = SshOutputFetchHandler;
        let mut ctx = create_test_context();
        let cache = Arc::new(OutputCache::new(300, 100));
        let id = cache
            .store("Hello, world! This is test output.".to_string())
            .await;
        ctx.output_cache = Some(cache);

        let result = handler
            .execute(Some(json!({"output_id": id})), &ctx)
            .await
            .unwrap();

        assert!(result.is_error.is_none());
        let text = get_text_content(&result);
        assert!(text.contains("Hello, world!"));
        assert!(text.contains("has_more=false"));
    }

    #[tokio::test]
    async fn test_fetch_with_offset_and_limit() {
        let handler = SshOutputFetchHandler;
        let mut ctx = create_test_context();
        let cache = Arc::new(OutputCache::new(300, 100));
        let content = "A".repeat(1000);
        let id = cache.store(content).await;
        ctx.output_cache = Some(cache);

        let result = handler
            .execute(
                Some(json!({"output_id": id, "offset": 100, "limit": 200})),
                &ctx,
            )
            .await
            .unwrap();

        let text = get_text_content(&result);
        assert!(text.contains("offset=100"));
        assert!(text.contains("has_more=true"));
        assert!(text.contains("chars=200/1000"));
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshOutputFetchHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"wrong_field": "value"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }
}
