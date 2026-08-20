//! Metrics Resource Handler
//!
//! Exposes system metrics as MCP resources.
//! URI format: `metrics://{host}`

use async_trait::async_trait;

use crate::domain::use_cases::parse_metrics::{self, SECTION_SEPARATOR, SystemMetrics};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Resource handler for system metrics
pub struct MetricsResourceHandler;

impl MetricsResourceHandler {
    /// Build the compound command to collect all metrics.
    const fn build_all_metrics_command() -> &'static str {
        "head -1 /proc/stat; nproc; \
         echo '---METRIC_SEP---'; \
         free -b; \
         echo '---METRIC_SEP---'; \
         df -B1; \
         echo '---METRIC_SEP---'; \
         cat /proc/net/dev; \
         echo '---METRIC_SEP---'; \
         cat /proc/loadavg; cat /proc/uptime"
    }

    /// Parse compound output into `SystemMetrics`.
    fn parse_all(stdout: &str, host: &str) -> SystemMetrics {
        let sections: Vec<&str> = stdout.split(SECTION_SEPARATOR).collect();

        SystemMetrics {
            host: host.to_string(),
            cpu: sections
                .first()
                .and_then(|s| parse_metrics::parse_cpu(s.trim())),
            memory: sections
                .get(1)
                .and_then(|s| parse_metrics::parse_memory(s.trim())),
            disk: sections
                .get(2)
                .and_then(|s| parse_metrics::parse_disk(s.trim())),
            network: sections
                .get(3)
                .and_then(|s| parse_metrics::parse_network(s.trim())),
            load: sections
                .get(4)
                .and_then(|s| parse_metrics::parse_load(s.trim())),
        }
    }
}

#[async_trait]
impl ResourceHandler for MetricsResourceHandler {
    fn scheme(&self) -> &'static str {
        "metrics"
    }

    fn description(&self) -> &'static str {
        "System metrics (CPU, memory, disk, network, load) from remote hosts"
    }

    async fn list(&self, ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        let mut resources = Vec::new();

        for (name, host_config) in &ctx.config.hosts {
            let desc = host_config
                .description
                .as_deref()
                .unwrap_or("System metrics");

            resources.push(ResourceDefinition {
                uri: format!("metrics://{name}"),
                name: format!("{name} metrics"),
                description: Some(desc.to_string()),
                mime_type: Some("application/json".to_string()),
            });
        }

        Ok(resources)
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        let host = uri
            .strip_prefix("metrics://")
            .ok_or_else(|| BridgeError::McpInvalidRequest(format!("Invalid metrics URI: {uri}")))?;

        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost {
                host: host.to_string(),
            })?;

        let command = Self::build_all_metrics_command();

        // Check rate limit
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
            "metrics_resource",
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

        let metrics = Self::parse_all(&output.stdout, host);
        let json = serde_json::to_string_pretty(&metrics)
            .unwrap_or_else(|e| format!("Error serializing metrics: {e}"));

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

    #[allow(clippy::too_many_lines)]
    fn create_ctx_with_hosts() -> ToolContext {
        let mut hosts = HashMap::new();
        hosts.insert(
            "web1".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: Some("Web server".to_string()),
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
            },
        );
        hosts.insert(
            "db1".to_string(),
            HostConfig {
                hostname: "10.0.0.2".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
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
            },
        );

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
    fn test_scheme() {
        let handler = MetricsResourceHandler;
        assert_eq!(handler.scheme(), "metrics");
        assert!(!handler.description().is_empty());
    }

    #[tokio::test]
    async fn test_list_resources_per_host() {
        let handler = MetricsResourceHandler;
        let ctx = create_ctx_with_hosts();

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources.len(), 2);

        let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(uris.contains(&"metrics://web1"));
        assert!(uris.contains(&"metrics://db1"));

        // Check that description is populated for web1
        let web1 = resources
            .iter()
            .find(|r| r.uri == "metrics://web1")
            .unwrap();
        assert_eq!(web1.description.as_deref(), Some("Web server"));
        assert_eq!(web1.mime_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn test_read_unknown_host() {
        let handler = MetricsResourceHandler;
        let ctx = create_ctx_with_hosts();

        let result = handler.read("metrics://unknown", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "unknown"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let handler = MetricsResourceHandler;
        let ctx = create_ctx_with_hosts();

        let result = handler.read("invalid://host", &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_all() {
        let stdout = format!(
            "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n{sep}\n\
             {mem}\n{sep}\n\
             {disk}\n{sep}\n\
             {net}\n{sep}\n\
             1.23 0.45 0.67 1/234 5678\n12345.67 98765.43\n",
            sep = SECTION_SEPARATOR,
            mem = "              total        used        free      shared  buff/cache   available\n\
                   Mem:    16000000000  8000000000  4000000000      100000  4000000000  7000000000\n\
                   Swap:    2000000000   500000000  1500000000",
            disk = "Filesystem     1B-blocks         Used    Available Use% Mounted on\n\
                    /dev/sda1    107374182400  53687091200  48318382080  53% /",
            net = "Inter-|   Receive                                                |  Transmit\n\
                    face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                    eth0: 12345678   1234    0    0    0     0          0         0 87654321   4321    0    0    0     0       0          0\n\
                      lo:     5678     90    0    0    0     0          0         0     5678     90    0    0    0     0       0          0"
        );

        let metrics = MetricsResourceHandler::parse_all(&stdout, "test-host");
        assert_eq!(metrics.host, "test-host");
        assert!(metrics.cpu.is_some());
        assert!(metrics.memory.is_some());
        assert!(metrics.disk.is_some());
        assert!(metrics.network.is_some());
        assert!(metrics.load.is_some());
    }
}
