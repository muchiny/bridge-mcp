use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::Result;

use super::client::{CommandOutput, SshClient};

/// A pooled SSH connection with metadata
struct PooledConnection {
    client: SshClient,
    created_at: Instant,
    last_used: Instant,
}

impl PooledConnection {
    fn new(client: SshClient) -> Self {
        let now = Instant::now();
        Self {
            client,
            created_at: now,
            last_used: now,
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }
}

/// Configuration for the connection pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per host
    pub max_connections_per_host: usize,
    /// Maximum idle time before connection is closed
    pub max_idle_seconds: u64,
    /// Maximum connection age before forced reconnection
    pub max_age_seconds: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 10,
            max_idle_seconds: 300, // 5 minutes
            max_age_seconds: 3600, // 1 hour
        }
    }
}

/// SSH connection pool for reusing connections
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    config: PoolConfig,
}

impl ConnectionPool {
    /// Create a new connection pool
    ///
    /// If `max_connections_per_host` is 0, it is silently clamped to 1
    /// to avoid a broken pool where every connection is immediately discarded.
    #[must_use]
    pub fn new(mut config: PoolConfig) -> Self {
        config.max_connections_per_host = config.max_connections_per_host.max(1);
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Create a pool with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PoolConfig::default())
    }

    /// Get or create a connection to the specified host
    ///
    /// # Errors
    ///
    /// Returns an error if a new connection cannot be established when no pooled
    /// connection is available.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<PooledConnectionGuard<'_>> {
        self.get_connection_with_jump(host_name, host_config, limits, None)
            .await
    }

    /// Get or create a connection to the specified host, optionally via a jump host
    ///
    /// # Arguments
    ///
    /// * `host_name` - The alias of the target host
    /// * `host_config` - Configuration of the target host
    /// * `limits` - Connection and command limits
    /// * `jump_host` - Optional tuple of (`jump_host_name`, `jump_host_config`) for bastion connections
    ///
    /// # Errors
    ///
    /// Returns an error if a new connection cannot be established when no pooled
    /// connection is available.
    #[tracing::instrument(
        name = "ssh.pool.get",
        skip(self, host_config, limits, jump_host),
        fields(
            host = %host_name,
            has_jump = jump_host.is_some(),
            from_cache = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        )
    )]
    pub async fn get_connection_with_jump(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
        jump_host: Option<(&str, &HostConfig)>,
    ) -> Result<PooledConnectionGuard<'_>> {
        let _timer = crate::telemetry::SpanDurationGuard::start();

        // Try to get an existing connection
        if let Some(conn) = self.try_get_existing(host_name).await {
            debug!(host = %host_name, "Reusing pooled connection");
            tracing::Span::current().record("from_cache", true);
            return Ok(PooledConnectionGuard {
                pool: self,
                host_name: host_name.to_string(),
                connection: Some(conn),
            });
        }
        tracing::Span::current().record("from_cache", false);

        // Create a new connection (direct or via jump host)
        let client = if let Some((jump_name, jump_config)) = jump_host {
            info!(
                host = %host_name,
                jump = %jump_name,
                "Creating new SSH connection via jump host"
            );
            SshClient::connect_via_jump(host_name, host_config, jump_name, jump_config, limits)
                .await?
        } else {
            info!(host = %host_name, "Creating new SSH connection");
            SshClient::connect(host_name, host_config, limits).await?
        };

        let conn = PooledConnection::new(client);

        Ok(PooledConnectionGuard {
            pool: self,
            host_name: host_name.to_string(),
            connection: Some(conn),
        })
    }

    /// Try to get an existing valid connection from the pool.
    ///
    /// **Security note:** Connections are keyed by host alias (`host_name`), which
    /// maps 1:1 to a `HostConfig` with a specific hostname/port. Host key
    /// verification (via `verify_host_key()`) is performed at connection creation
    /// time, ensuring that each pooled connection was authenticated against the
    /// correct remote host. DNS poisoning after initial connection does not affect
    /// already-established SSH sessions because the transport is encrypted and
    /// integrity-checked.
    async fn try_get_existing(&self, host_name: &str) -> Option<PooledConnection> {
        let max_idle = Duration::from_secs(self.config.max_idle_seconds);
        let max_age = Duration::from_secs(self.config.max_age_seconds);

        // Take all candidate connections while holding the lock
        let candidates: Vec<_> = {
            let mut connections = self.connections.lock().await;
            connections
                .get_mut(host_name)
                .map(std::mem::take)
                .unwrap_or_default()
        }; // Lock released here

        let mut to_return = Vec::new();
        let mut result = None;

        for mut conn in candidates {
            if result.is_some() {
                // Already found a valid connection, keep this one for later
                to_return.push(conn);
                continue;
            }

            // Check if connection is still valid
            if conn.idle_time() > max_idle {
                debug!(host = %host_name, idle_secs = ?conn.idle_time().as_secs(), "Connection too idle, closing");
                let _ = conn.client.close().await;
                continue;
            }

            if conn.age() > max_age {
                debug!(host = %host_name, age_secs = ?conn.age().as_secs(), "Connection too old, closing");
                let _ = conn.client.close().await;
                continue;
            }

            // Check if connection is still alive
            if !conn.client.is_connected().await {
                debug!(host = %host_name, "Connection dead, discarding");
                continue;
            }

            conn.touch();
            result = Some(conn);
        }

        // Return unused valid connections to the pool
        if !to_return.is_empty() {
            let mut connections = self.connections.lock().await;
            connections
                .entry(host_name.to_string())
                .or_default()
                .extend(to_return);
            drop(connections);
        }

        result
    }

    /// Clean up idle and old connections (time-based, no health check)
    pub async fn cleanup(&self) {
        let mut connections = self.connections.lock().await;

        let max_idle = Duration::from_secs(self.config.max_idle_seconds);
        let max_age = Duration::from_secs(self.config.max_age_seconds);

        // Collect expired connections so we can close them properly
        let mut expired: Vec<(String, PooledConnection)> = Vec::new();

        for (host_name, host_connections) in connections.iter_mut() {
            let before = host_connections.len();
            let mut i = 0;
            while i < host_connections.len() {
                if host_connections[i].idle_time() > max_idle || host_connections[i].age() > max_age
                {
                    expired.push((host_name.clone(), host_connections.swap_remove(i)));
                } else {
                    i += 1;
                }
            }

            let after = host_connections.len();
            if before != after {
                info!(
                    host = %host_name,
                    closed = before - after,
                    remaining = after,
                    "Cleaned up idle connections"
                );
            }
        }

        // Remove empty entries
        connections.retain(|_, v| !v.is_empty());
        drop(connections); // Release lock before closing connections

        // Close SSH connections properly (sends SSH DISCONNECT)
        for (host_name, conn) in expired {
            if let Err(e) = conn.client.close().await {
                warn!(host = %host_name, error = %e, "Failed to close expired connection");
            }
        }
    }

    /// Actively check all pooled connections and remove dead ones
    ///
    /// Unlike `cleanup()` which only removes time-expired connections, this method
    /// actually tests each connection by opening a channel. This is more expensive
    /// but catches connections that are dead due to network issues, host reboots, etc.
    pub async fn health_check(&self) {
        // Take all connections out of the pool to check them
        let to_check: Vec<(String, Vec<PooledConnection>)> = {
            let mut connections = self.connections.lock().await;
            connections.drain().collect()
        };

        let mut healthy: HashMap<String, Vec<PooledConnection>> = HashMap::new();
        let mut dead_count = 0;

        for (host_name, host_connections) in to_check {
            for conn in host_connections {
                if conn.client.is_connected().await {
                    healthy.entry(host_name.clone()).or_default().push(conn);
                } else {
                    warn!(host = %host_name, "Dead connection removed during health check");
                    dead_count += 1;
                    // Connection is dropped, triggering cleanup
                }
            }
        }

        // Put healthy connections back
        if !healthy.is_empty() {
            let mut connections = self.connections.lock().await;
            for (host, conns) in healthy {
                connections.entry(host).or_default().extend(conns);
            }
        }

        if dead_count > 0 {
            info!(
                removed = dead_count,
                "Health check completed, removed dead connections"
            );
        } else {
            debug!("Health check completed, all connections healthy");
        }
    }

    /// Get pool statistics
    #[must_use = "pool stats should be used for monitoring or logging"]
    pub async fn stats(&self) -> PoolStats {
        let connections = self.connections.lock().await;
        let mut total = 0;
        let mut by_host = HashMap::new();

        for (host, conns) in connections.iter() {
            let count = conns.len();
            total += count;
            by_host.insert(host.clone(), count);
        }

        drop(connections); // Release lock before constructing result

        PoolStats {
            total_connections: total,
            connections_by_host: by_host,
        }
    }

    /// Close all connections and clear the pool
    pub async fn close_all(&self) {
        let to_close: Vec<_> = {
            let mut connections = self.connections.lock().await;
            connections.drain().collect()
        }; // Lock released here

        for (host_name, host_connections) in to_close {
            for conn in host_connections {
                debug!(host = %host_name, "Closing pooled connection");
                let _ = conn.client.close().await;
            }
        }

        info!("Connection pool closed");
    }
}

/// Statistics about the connection pool
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub connections_by_host: HashMap<String, usize>,
}

/// Guard that returns connection to pool on drop
pub struct PooledConnectionGuard<'a> {
    pool: &'a ConnectionPool,
    host_name: String,
    connection: Option<PooledConnection>,
}

impl PooledConnectionGuard<'_> {
    /// Execute a command using this connection
    ///
    /// # Errors
    ///
    /// Returns an error if the command execution fails, or if the
    /// underlying connection handle has already been consumed (e.g., after
    /// `mark_failed` was called). The latter is reported as a structured
    /// `BridgeError::SshConnection` rather than a panic so the calling
    /// tool surfaces a clean MCP error instead of crashing the process.
    pub async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        self.exec_with_stdin(command, None, limits).await
    }

    /// Like [`Self::exec`], but feeds `stdin` to the remote command's stdin
    /// over the SSH channel (then EOF) instead of through the command text.
    ///
    /// # Errors
    ///
    /// Same as [`Self::exec`].
    pub async fn exec_with_stdin(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        limits: &LimitsConfig,
    ) -> Result<CommandOutput> {
        let conn =
            self.connection
                .as_mut()
                .ok_or_else(|| crate::error::BridgeError::SshConnection {
                    host: self.host_name.clone(),
                    reason: "pooled connection handle missing (already taken or never initialized)"
                        .to_string(),
                })?;
        conn.touch();
        conn.client.exec_with_stdin(command, stdin, limits).await
    }

    /// Mark this connection as failed (won't be returned to pool)
    pub fn mark_failed(&mut self) {
        if let Some(conn) = self.connection.take() {
            let host = self.host_name.clone();
            warn!(host = %host, "Connection marked as failed, will not return to pool");
            // Close the connection in background (can't await in sync context)
            tokio::spawn(async move {
                if let Err(e) = conn.client.close().await {
                    warn!(host = %host, error = %e, "Failed to close failed connection");
                }
            });
        }
    }
}

impl Drop for PooledConnectionGuard<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            let pool = self.pool.connections.clone();
            let host_name = self.host_name.clone();
            let max_per_host = self.pool.config.max_connections_per_host;

            // Return to pool in background (can't await in Drop)
            tokio::spawn(async move {
                let mut connections = pool.lock().await;
                let host_connections = connections.entry(host_name.clone()).or_default();

                if host_connections.len() < max_per_host {
                    host_connections.push(conn);
                } else {
                    drop(connections); // Release lock before closing
                    if let Err(e) = conn.client.close().await {
                        warn!(host = %host_name, error = %e, "Failed to close excess connection");
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.max_idle_seconds, 300);
        assert_eq!(config.max_age_seconds, 3600);
    }

    #[test]
    fn test_pool_config_custom() {
        let config = PoolConfig {
            max_connections_per_host: 10,
            max_idle_seconds: 60,
            max_age_seconds: 1800,
        };
        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.max_idle_seconds, 60);
        assert_eq!(config.max_age_seconds, 1800);
    }

    #[test]
    fn test_pool_config_clone_and_debug() {
        let config = PoolConfig::default();
        let cloned = config.clone();

        assert_eq!(
            config.max_connections_per_host,
            cloned.max_connections_per_host
        );
        assert_eq!(config.max_idle_seconds, cloned.max_idle_seconds);
        assert_eq!(config.max_age_seconds, cloned.max_age_seconds);

        // Test Debug trait
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("PoolConfig"));
    }

    #[tokio::test]
    async fn test_pool_stats_empty() {
        let pool = ConnectionPool::with_defaults();
        let stats = pool.stats().await;

        assert_eq!(stats.total_connections, 0);
        assert!(stats.connections_by_host.is_empty());
    }

    #[tokio::test]
    async fn test_pool_stats_clone_and_debug() {
        let pool = ConnectionPool::with_defaults();
        let stats = pool.stats().await;

        let cloned = stats.clone();
        assert_eq!(stats.total_connections, cloned.total_connections);

        // Test Debug trait
        let debug_str = format!("{stats:?}");
        assert!(debug_str.contains("PoolStats"));
    }

    #[tokio::test]
    async fn test_pool_cleanup_empty() {
        let pool = ConnectionPool::with_defaults();
        // Should not panic on empty pool
        pool.cleanup().await;

        // Stats should still be empty
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_close_all_empty() {
        let pool = ConnectionPool::with_defaults();
        // Should not panic on empty pool
        pool.close_all().await;

        // Stats should still be empty
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_multiple_cleanup_calls() {
        let pool = ConnectionPool::with_defaults();

        // Multiple cleanup calls should not panic
        pool.cleanup().await;
        pool.cleanup().await;
        pool.cleanup().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_with_custom_config() {
        let config = PoolConfig {
            max_connections_per_host: 2,
            max_idle_seconds: 10,
            max_age_seconds: 60,
        };
        let pool = ConnectionPool::new(config);

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_health_check_empty() {
        let pool = ConnectionPool::with_defaults();
        // Should not panic on empty pool
        pool.health_check().await;

        // Stats should still be empty
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_multiple_health_check_calls() {
        let pool = ConnectionPool::with_defaults();

        // Multiple health check calls should not panic
        pool.health_check().await;
        pool.health_check().await;
        pool.health_check().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    // ============== PoolConfig Edge Cases ==============

    #[test]
    fn test_pool_config_zero_connections() {
        let config = PoolConfig {
            max_connections_per_host: 0,
            max_idle_seconds: 300,
            max_age_seconds: 3600,
        };
        // Raw config allows 0, but ConnectionPool::new() clamps to 1
        assert_eq!(config.max_connections_per_host, 0);
    }

    #[test]
    fn test_pool_config_very_short_timeouts() {
        let config = PoolConfig {
            max_connections_per_host: 5,
            max_idle_seconds: 1,
            max_age_seconds: 1,
        };
        assert_eq!(config.max_idle_seconds, 1);
        assert_eq!(config.max_age_seconds, 1);
    }

    #[test]
    fn test_pool_config_very_long_timeouts() {
        let config = PoolConfig {
            max_connections_per_host: 100,
            max_idle_seconds: 86_400, // 1 day
            max_age_seconds: 604_800, // 1 week
        };
        assert_eq!(config.max_idle_seconds, 86_400);
        assert_eq!(config.max_age_seconds, 604_800);
    }

    #[test]
    fn test_pool_config_idle_longer_than_age() {
        // Edge case: idle timeout > max age (unusual but valid config)
        let config = PoolConfig {
            max_connections_per_host: 5,
            max_idle_seconds: 7200,
            max_age_seconds: 3600,
        };
        assert!(config.max_idle_seconds > config.max_age_seconds);
    }

    // ============== PoolStats Tests ==============

    #[tokio::test]
    async fn test_pool_stats_total_connections_accuracy() {
        let pool = ConnectionPool::with_defaults();
        let stats = pool.stats().await;

        // Empty pool should have consistent stats
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.connections_by_host.len(), 0);
    }

    #[tokio::test]
    async fn test_pool_stats_immutability() {
        let pool = ConnectionPool::with_defaults();
        let stats1 = pool.stats().await;
        let stats2 = pool.stats().await;

        // Stats should be consistent between calls on empty pool
        assert_eq!(stats1.total_connections, stats2.total_connections);
    }

    #[test]
    fn test_pool_stats_debug_format() {
        let stats = PoolStats {
            total_connections: 5,
            connections_by_host: {
                let mut map = std::collections::HashMap::new();
                map.insert("host1".to_string(), 3);
                map.insert("host2".to_string(), 2);
                map
            },
        };

        let debug_str = format!("{stats:?}");
        assert!(debug_str.contains("PoolStats"));
        assert!(debug_str.contains("total_connections"));
        assert!(debug_str.contains('5'));
    }

    #[test]
    fn test_pool_stats_clone_preserves_all_data() {
        let stats = PoolStats {
            total_connections: 10,
            connections_by_host: {
                let mut map = std::collections::HashMap::new();
                map.insert("server1".to_string(), 4);
                map.insert("server2".to_string(), 6);
                map
            },
        };

        let cloned = stats.clone();
        assert_eq!(cloned.total_connections, 10);
        assert_eq!(cloned.connections_by_host.len(), 2);
        assert_eq!(cloned.connections_by_host.get("server1"), Some(&4));
        assert_eq!(cloned.connections_by_host.get("server2"), Some(&6));
    }

    // ============== Pool Creation Tests ==============

    #[tokio::test]
    async fn test_pool_new_with_zero_max_connections_clamped() {
        let config = PoolConfig {
            max_connections_per_host: 0,
            max_idle_seconds: 300,
            max_age_seconds: 3600,
        };
        let pool = ConnectionPool::new(config);
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
        // Verify the pool clamped max_connections_per_host to 1
        assert_eq!(pool.config.max_connections_per_host, 1);
    }

    #[tokio::test]
    async fn test_pool_new_with_minimal_config() {
        let config = PoolConfig {
            max_connections_per_host: 1,
            max_idle_seconds: 1,
            max_age_seconds: 1,
        };
        let pool = ConnectionPool::new(config);
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    // ============== Concurrent Operations Tests ==============

    #[tokio::test]
    async fn test_pool_concurrent_stats_access() {
        let pool = std::sync::Arc::new(ConnectionPool::with_defaults());

        let mut handles = vec![];
        for _ in 0..10 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move { pool_clone.stats().await }));
        }

        for handle in handles {
            let stats = handle.await.unwrap();
            assert_eq!(stats.total_connections, 0);
        }
    }

    #[tokio::test]
    async fn test_pool_concurrent_cleanup_calls() {
        let pool = std::sync::Arc::new(ConnectionPool::with_defaults());

        let mut handles = vec![];
        for _ in 0..10 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move {
                pool_clone.cleanup().await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_concurrent_health_check_calls() {
        let pool = std::sync::Arc::new(ConnectionPool::with_defaults());

        let mut handles = vec![];
        for _ in 0..5 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move {
                pool_clone.health_check().await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    // ============== Pool Lifecycle Tests ==============

    #[tokio::test]
    async fn test_pool_cleanup_then_close_all() {
        let pool = ConnectionPool::with_defaults();

        pool.cleanup().await;
        pool.close_all().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_close_all_then_cleanup() {
        let pool = ConnectionPool::with_defaults();

        pool.close_all().await;
        pool.cleanup().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_health_check_then_close_all() {
        let pool = ConnectionPool::with_defaults();

        pool.health_check().await;
        pool.close_all().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_reuse_after_close_all() {
        let pool = ConnectionPool::with_defaults();

        pool.close_all().await;
        // Pool should still be usable after close_all
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);

        pool.cleanup().await;
        pool.health_check().await;
    }

    // ============== PoolConfig Additional Tests ==============

    #[test]
    fn test_pool_config_max_u64_timeouts() {
        let config = PoolConfig {
            max_connections_per_host: usize::MAX,
            max_idle_seconds: u64::MAX,
            max_age_seconds: u64::MAX,
        };
        assert_eq!(config.max_connections_per_host, usize::MAX);
        assert_eq!(config.max_idle_seconds, u64::MAX);
        assert_eq!(config.max_age_seconds, u64::MAX);
    }

    #[test]
    fn test_pool_config_default_values_reasonable() {
        let config = PoolConfig::default();

        // At least 1 connection per host
        assert!(config.max_connections_per_host >= 1);

        // Idle timeout should be less than max age
        assert!(config.max_idle_seconds <= config.max_age_seconds);

        // Timeouts should be at least 1 second
        assert!(config.max_idle_seconds >= 1);
        assert!(config.max_age_seconds >= 1);
    }

    // ============== PoolStats Additional Tests ==============

    #[test]
    fn test_pool_stats_with_multiple_hosts() {
        let mut by_host = std::collections::HashMap::new();
        by_host.insert("host1".to_string(), 5);
        by_host.insert("host2".to_string(), 3);
        by_host.insert("host3".to_string(), 2);

        let stats = PoolStats {
            total_connections: 10,
            connections_by_host: by_host,
        };

        assert_eq!(stats.total_connections, 10);
        assert_eq!(stats.connections_by_host.len(), 3);
        assert_eq!(stats.connections_by_host.get("host1"), Some(&5));
        assert_eq!(stats.connections_by_host.get("host2"), Some(&3));
        assert_eq!(stats.connections_by_host.get("host3"), Some(&2));
    }

    #[test]
    fn test_pool_stats_empty_hosts_map() {
        let stats = PoolStats {
            total_connections: 0,
            connections_by_host: std::collections::HashMap::new(),
        };

        assert!(stats.connections_by_host.is_empty());
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn test_pool_stats_inconsistent_total() {
        // This shouldn't happen in practice but tests the struct
        let mut by_host = std::collections::HashMap::new();
        by_host.insert("host".to_string(), 5);

        let stats = PoolStats {
            total_connections: 100, // Doesn't match sum of by_host
            connections_by_host: by_host,
        };

        // The struct allows this (no validation)
        assert_eq!(stats.total_connections, 100);
    }

    // ============== Pool Operations Ordering Tests ==============

    #[tokio::test]
    async fn test_pool_operations_sequence() {
        let pool = ConnectionPool::with_defaults();

        // Sequence: stats -> cleanup -> stats -> health_check -> stats -> close_all -> stats
        let s1 = pool.stats().await;
        assert_eq!(s1.total_connections, 0);

        pool.cleanup().await;
        let s2 = pool.stats().await;
        assert_eq!(s2.total_connections, 0);

        pool.health_check().await;
        let s3 = pool.stats().await;
        assert_eq!(s3.total_connections, 0);

        pool.close_all().await;
        let s4 = pool.stats().await;
        assert_eq!(s4.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_interleaved_operations() {
        let pool = std::sync::Arc::new(ConnectionPool::with_defaults());

        let pool1 = pool.clone();
        let pool2 = pool.clone();
        let pool3 = pool.clone();

        // Interleave different operations
        let h1 = tokio::spawn(async move { pool1.cleanup().await });
        let h2 = tokio::spawn(async move {
            let _ = pool2.stats().await;
        });
        let h3 = tokio::spawn(async move { pool3.health_check().await });

        let _ = h1.await;
        let _ = h2.await;
        let _ = h3.await;

        // Pool should still be functional
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    // ============== PoolConfig Comparison Tests ==============

    #[test]
    fn test_pool_config_different_instances() {
        let config1 = PoolConfig::default();
        let config2 = PoolConfig::default();

        // Different instances with same values
        assert_eq!(
            config1.max_connections_per_host,
            config2.max_connections_per_host
        );
        assert_eq!(config1.max_idle_seconds, config2.max_idle_seconds);
        assert_eq!(config1.max_age_seconds, config2.max_age_seconds);
    }

    #[test]
    fn test_pool_config_modified_values() {
        let mut config = PoolConfig::default();
        let original_max = config.max_connections_per_host;

        config.max_connections_per_host = 99;
        assert_ne!(config.max_connections_per_host, original_max);
        assert_eq!(config.max_connections_per_host, 99);
    }

    // ============== Pool with Custom Config Tests ==============

    #[tokio::test]
    async fn test_pool_custom_config_minimal() {
        let config = PoolConfig {
            max_connections_per_host: 1,
            max_idle_seconds: 1,
            max_age_seconds: 1,
        };
        let pool = ConnectionPool::new(config);

        // Should work with minimal config
        pool.cleanup().await;
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_custom_config_high_limits() {
        let config = PoolConfig {
            max_connections_per_host: 1000,
            max_idle_seconds: 86400,  // 1 day
            max_age_seconds: 604_800, // 1 week
        };
        let pool = ConnectionPool::new(config);

        pool.health_check().await;
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    // ============== Drop Behavior Tests ==============

    #[tokio::test]
    async fn test_pool_drop_without_close() {
        {
            let pool = ConnectionPool::with_defaults();
            let _stats = pool.stats().await;
            // Pool is dropped here without calling close_all
        }
        // Should not panic or hang
    }

    #[tokio::test]
    async fn test_pool_stats_after_new() {
        let pool = ConnectionPool::with_defaults();

        // Immediately after creation, pool should be empty
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
        assert!(stats.connections_by_host.is_empty());
    }
}
