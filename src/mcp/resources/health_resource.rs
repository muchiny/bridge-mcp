//! Health Resource Handler
//!
//! Exposes server health and status as an MCP resource.
//! URI format: `health://server`

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};

/// Resource handler for server health
pub struct HealthResourceHandler;

#[async_trait]
impl ResourceHandler for HealthResourceHandler {
    fn scheme(&self) -> &'static str {
        "health"
    }

    fn description(&self) -> &'static str {
        "Bridge MCP server health and status"
    }

    async fn list(&self, _ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        Ok(vec![ResourceDefinition {
            uri: "health://server".to_string(),
            name: "Server Health".to_string(),
            description: Some("Bridge MCP server health and status".to_string()),
            mime_type: Some("application/json".to_string()),
        }])
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        if uri != "health://server" {
            return Err(crate::error::BridgeError::McpInvalidRequest(format!(
                "Invalid health URI: {uri}. Only 'health://server' is supported."
            )));
        }

        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let health = serde_json::json!({
            "status": "healthy",
            "hosts_configured": ctx.config.hosts.len(),
            "security_mode": format!("{:?}", ctx.config.security.mode),
            "timestamp": uptime,
        });

        let json = serde_json::to_string_pretty(&health)
            .unwrap_or_else(|e| format!("Error serializing health: {e}"));

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("application/json".to_string()),
            text: Some(json),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_scheme() {
        let handler = HealthResourceHandler;
        assert_eq!(handler.scheme(), "health");
        assert!(!handler.description().is_empty());
    }

    #[tokio::test]
    async fn test_list_returns_single_resource() {
        let handler = HealthResourceHandler;
        let ctx = create_test_context();

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "health://server");
        assert_eq!(resources[0].name, "Server Health");
        assert_eq!(resources[0].mime_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn test_read_health() {
        let handler = HealthResourceHandler;
        let ctx = create_test_context();

        let contents = handler.read("health://server", &ctx).await.unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].uri, "health://server");

        let text = contents[0].text.as_deref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["status"], "healthy");
        assert!(parsed["hosts_configured"].is_number());
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let handler = HealthResourceHandler;
        let ctx = create_test_context();

        let result = handler.read("health://unknown", &ctx).await;
        assert!(result.is_err());
    }
}
