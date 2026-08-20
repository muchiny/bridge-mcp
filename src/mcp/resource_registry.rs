//! Resource Registry
//!
//! Manages registration and lookup of MCP resource handlers.

use std::sync::Arc;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};

/// Registry for MCP resource handlers
#[derive(Default)]
pub struct ResourceRegistry {
    handlers: Vec<Arc<dyn ResourceHandler>>,
}

impl ResourceRegistry {
    /// Create a new empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a resource handler
    pub fn register(&mut self, handler: Arc<dyn ResourceHandler>) {
        self.handlers.push(handler);
    }

    /// List all available resources from all handlers
    ///
    /// # Errors
    ///
    /// This function logs warnings for handler failures but does not
    /// propagate errors; it always returns `Ok` with the successfully
    /// collected resources.
    pub async fn list(&self, ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        let mut all_resources = Vec::new();
        for handler in &self.handlers {
            match handler.list(ctx).await {
                Ok(resources) => all_resources.extend(resources),
                Err(e) => {
                    tracing::warn!(
                        scheme = handler.scheme(),
                        error = %e,
                        "Failed to list resources"
                    );
                }
            }
        }
        Ok(all_resources)
    }

    /// Read a resource by URI, routing to the appropriate handler
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URI format is invalid (missing scheme)
    /// - No handler is registered for the URI scheme
    /// - The handler fails to read the resource
    pub async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        let scheme = uri
            .split("://")
            .next()
            .ok_or_else(|| BridgeError::McpInvalidRequest(format!("Invalid URI: {uri}")))?;

        let handler = self
            .handlers
            .iter()
            .find(|h| h.scheme() == scheme)
            .ok_or_else(|| {
                BridgeError::McpInvalidRequest(format!("Unsupported resource scheme: {scheme}"))
            })?;

        handler.read(uri, ctx).await
    }

    /// Handlers that publish a per-host URI template instead of a concrete
    /// listing (their `list()` returns an empty Vec by design).
    pub fn templated_handlers(&self) -> impl Iterator<Item = &Arc<dyn ResourceHandler>> {
        self.handlers.iter().filter(|h| h.path_template().is_some())
    }

    /// Every URI scheme that has a registered handler.
    ///
    /// Used by `resources/templates/list` tests to prove that every published
    /// `uriTemplate` can actually be routed by `read`.
    ///
    /// `#[cfg(test)]` (fix round 1, audit 2026-08-19, MINOR): its only
    /// caller is a same-crate test, unlike `templated_handlers`, which
    /// `handle_resource_templates_list` actually calls in production. New
    /// public API with no production caller is exactly the pattern this
    /// batch exists to delete; `pub(crate)` alone still left it flagged as
    /// dead code in a non-test build, so it is test-only rather than
    /// merely crate-scoped.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn schemes(&self) -> Vec<&'static str> {
        self.handlers.iter().map(|h| h.scheme()).collect()
    }

    /// Get the number of registered handlers
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// Create the default resource registry with all built-in resource handlers
#[must_use]
pub fn create_default_resource_registry() -> ResourceRegistry {
    use super::resources::{
        FileResourceHandler, HealthResourceHandler, HistoryResourceHandler, LogResourceHandler,
        MetricsResourceHandler, ServicesResourceHandler,
    };

    let mut registry = ResourceRegistry::new();

    registry.register(Arc::new(MetricsResourceHandler));
    registry.register(Arc::new(LogResourceHandler));
    registry.register(Arc::new(FileResourceHandler));
    registry.register(Arc::new(ServicesResourceHandler));
    registry.register(Arc::new(HistoryResourceHandler));
    registry.register(Arc::new(HealthResourceHandler));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, Config, HttpTransportConfig, LimitsConfig, SecurityConfig, SessionConfig,
        SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::domain::{ExecuteCommandUseCase, TunnelManager};
    use crate::mcp::CommandHistory;
    use crate::mcp::history::HistoryConfig;
    use crate::ports::ExecutorRouter;
    use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
    use crate::ssh::SessionManager;
    use std::collections::HashMap;

    fn create_test_context() -> ToolContext {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let validator = Arc::new(CommandValidator::new(&SecurityConfig::default()));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            pending_requests: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    #[test]
    fn test_resource_registry_new() {
        let registry = ResourceRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_resource_registry_default() {
        let registry = ResourceRegistry::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_default_resource_registry_has_all_handlers() {
        let registry = create_default_resource_registry();
        assert_eq!(registry.len(), 6);
        assert!(!registry.is_empty());
    }

    #[tokio::test]
    async fn test_list_returns_resources() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let resources = registry.list(&ctx).await.unwrap();
        // With no hosts configured, only host-independent resources are listed.
        // history://recent and health://server are always present regardless of host config.
        assert_eq!(resources.len(), 2);
        let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(uris.contains(&"history://recent"));
        assert!(uris.contains(&"health://server"));
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("invalid-no-scheme", &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_unsupported_scheme() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("ftp://server/file", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("ftp"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_list_on_empty_registry() {
        let registry = ResourceRegistry::new();
        let ctx = create_test_context();

        let resources = registry.list(&ctx).await.unwrap();
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn test_read_on_empty_registry() {
        let registry = ResourceRegistry::new();
        let ctx = create_test_context();

        let result = registry.read("metrics://server1/cpu", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("metrics"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_register_multiple_handlers() {
        use super::super::resources::{FileResourceHandler, LogResourceHandler};

        let mut registry = ResourceRegistry::new();
        assert!(registry.is_empty());

        registry.register(Arc::new(FileResourceHandler));
        assert_eq!(registry.len(), 1);

        registry.register(Arc::new(LogResourceHandler));
        assert_eq!(registry.len(), 2);
    }

    #[tokio::test]
    async fn test_read_history_scheme_works() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("history://recent", &ctx).await;
        assert!(result.is_ok());
        let contents = result.unwrap();
        assert!(!contents.is_empty());
    }

    #[tokio::test]
    async fn test_read_unsupported_scheme_error_message_format() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("custom://data", &ctx).await;
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("Unsupported resource scheme"));
                assert!(msg.contains("custom"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_read_health_scheme_works() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("health://server", &ctx).await;
        assert!(result.is_ok());
        let contents = result.unwrap();
        assert!(!contents.is_empty());
        // Health resource should return JSON content
        assert_eq!(contents[0].mime_type, Some("application/json".to_string()));
    }

    #[tokio::test]
    async fn test_read_invalid_uri_no_separator() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        // URI with no :// separator still extracts the part before ://
        // "just-a-string" has no "://", so split returns the whole string
        let result = registry.read("just-a-string", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("Unsupported resource scheme"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_list_returns_resources_with_valid_uris() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let resources = registry.list(&ctx).await.unwrap();
        for resource in &resources {
            assert!(
                resource.uri.contains("://"),
                "Resource URI {} should contain ://",
                resource.uri
            );
        }
    }

    #[tokio::test]
    async fn test_read_routes_to_correct_handler() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        // history scheme should be handled by HistoryResourceHandler
        let history_result = registry.read("history://recent", &ctx).await;
        assert!(history_result.is_ok());

        // health scheme should be handled by HealthResourceHandler
        let health_result = registry.read("health://server", &ctx).await;
        assert!(health_result.is_ok());

        // metrics scheme with no host configured will fail at the handler level,
        // but it should be routed (not "unsupported scheme")
        let metrics_result = registry.read("metrics://nonexistent/cpu", &ctx).await;
        // This should fail because no host "nonexistent" exists, but the error
        // should NOT be "Unsupported resource scheme"
        if let Err(BridgeError::McpInvalidRequest(msg)) = metrics_result {
            assert!(
                !msg.contains("Unsupported resource scheme"),
                "metrics:// should be routed to handler, not rejected as unsupported"
            );
        }
    }
}
