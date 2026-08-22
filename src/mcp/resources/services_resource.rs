//! Services Resource Handler
//!
//! Exposes systemd service status as MCP resources.
//! URI format: `services://{host}`

use async_trait::async_trait;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Resource handler for systemd service status
pub struct ServicesResourceHandler;

#[async_trait]
impl ResourceHandler for ServicesResourceHandler {
    fn scheme(&self) -> &'static str {
        "services"
    }

    fn description(&self) -> &'static str {
        "Systemd service status from remote hosts"
    }

    async fn list(&self, ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        let mut resources = Vec::new();

        for (name, host_config) in &ctx.config.hosts {
            let desc = host_config
                .description
                .as_deref()
                .unwrap_or("Systemd services");

            resources.push(ResourceDefinition {
                uri: format!("services://{name}"),
                name: format!("{name} services"),
                description: Some(desc.to_string()),
                mime_type: Some("text/plain".to_string()),
            });
        }

        Ok(resources)
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        let host = uri.strip_prefix("services://").ok_or_else(|| {
            BridgeError::McpInvalidRequest(format!("Invalid services URI: {uri}"))
        })?;

        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost {
                host: host.to_string(),
            })?;

        let command = "systemctl list-units --type=service --no-pager --no-legend 2>/dev/null \
                        || service --status-all 2>/dev/null \
                        || echo 'No service manager found'";

        if ctx.rate_limiter.check(host).is_err() {
            return Err(BridgeError::RateLimitExceeded {
                host: host.to_string(),
            });
        }

        let limits = ctx.config.limits.clone();
        let retry_config = limits.retry_config();

        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jc| (jump_name.as_str(), jc))
        });

        let output = with_retry_if(
            &retry_config,
            "services_resource",
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(host, host_config, &limits, jump_host)
                    .await?;

                match conn.exec(command, &limits).await {
                    Ok(out) => Ok(out),
                    Err(e) => {
                        conn.mark_failed();
                        Err(e)
                    }
                }
            },
            is_retryable_error,
        )
        .await?;

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(output.stdout),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, HttpTransportConfig,
        LimitsConfig, OsType, SecurityConfig, SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::domain::{ExecuteCommandUseCase, TunnelManager};
    use crate::mcp::CommandHistory;
    use crate::mcp::history::HistoryConfig;
    use crate::ports::ExecutorRouter;
    use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
    use crate::ssh::SessionManager;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Build a Linux `HostConfig` with the given optional description.
    fn sample_host_config(description: Option<String>) -> HostConfig {
        HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 22,
            user: "admin".to_string(),
            auth: AuthConfig::Key {
                path: "~/.ssh/id_rsa".to_string(),
                passphrase: None,
            },
            description,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::Linux,
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
            #[cfg(feature = "winrm")]
            winrm_use_tls: None,
            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,
            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,
            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        }
    }

    /// Build a `ToolContext` around the given host map (rate limiting disabled).
    fn build_ctx(hosts: HashMap<String, HostConfig>) -> ToolContext {
        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // Test fixture: AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log).
            audit: AuditConfig {
                enabled: false,
                ..AuditConfig::default()
            },
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
            mrtr: crate::ports::MrtrSlot::default(),
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
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    fn create_ctx_with_hosts() -> ToolContext {
        let mut hosts = HashMap::new();
        hosts.insert(
            "app1".to_string(),
            sample_host_config(Some("Application server".to_string())),
        );
        build_ctx(hosts)
    }

    #[test]
    fn test_scheme() {
        let handler = ServicesResourceHandler;
        assert_eq!(handler.scheme(), "services");
        assert!(!handler.description().is_empty());
    }

    #[tokio::test]
    async fn test_list_resources_per_host() {
        let handler = ServicesResourceHandler;
        let ctx = create_ctx_with_hosts();

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "services://app1");
        assert_eq!(
            resources[0].description.as_deref(),
            Some("Application server")
        );
        assert_eq!(resources[0].mime_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn test_read_unknown_host() {
        let handler = ServicesResourceHandler;
        let ctx = create_ctx_with_hosts();

        let result = handler.read("services://unknown", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "unknown"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let handler = ServicesResourceHandler;
        let ctx = create_ctx_with_hosts();

        let result = handler.read("invalid://host", &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_resource_name_and_mime() {
        let handler = ServicesResourceHandler;
        let ctx = create_ctx_with_hosts();

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources[0].name, "app1 services");
        assert_eq!(resources[0].mime_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn test_list_default_description_when_host_has_none() {
        let handler = ServicesResourceHandler;
        let mut hosts = HashMap::new();
        hosts.insert("bare".to_string(), sample_host_config(None));
        let ctx = build_ctx(hosts);

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "services://bare");
        assert_eq!(resources[0].name, "bare services");
        // Missing description falls back to the generic label
        assert_eq!(
            resources[0].description.as_deref(),
            Some("Systemd services")
        );
    }

    #[tokio::test]
    async fn test_list_empty_when_no_hosts() {
        let handler = ServicesResourceHandler;
        let ctx = build_ctx(HashMap::new());

        let resources = handler.list(&ctx).await.unwrap();
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn test_read_empty_host_is_unknown() {
        // "services://" strips to an empty host string, which is not configured
        let handler = ServicesResourceHandler;
        let ctx = create_ctx_with_hosts();

        let result = handler.read("services://", &ctx).await;
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, ""),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }
}
