//! PSRP connection pool — caches `WinrmClient` instances per host.
//!
//! Longer TTL than `WinRM` (300 s vs 120 s) because the PSRP handshake
//! (TLS + auth + PSRP session open) is more expensive than plain `WinRM`.
//!
//! The pool caches `Arc<WinrmClient>` — the same approach as `WinRmPool`.
//! Each `PsrpConnection::exec()` creates a scoped `RunspacePool` from
//! the cached client, avoiding the TLS/auth overhead while working
//! within Rust's lifetime constraints.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info};

use super::PsrpConnection;
use crate::config::{HostConfig, LimitsConfig};
use crate::error::Result;

/// Default idle TTL for cached `WinrmClient` entries in the PSRP pool.
const DEFAULT_PSRP_IDLE_TTL: Duration = Duration::from_secs(300);

/// A cached entry: one `WinrmClient` + last-used timestamp.
struct PooledClient {
    client: Arc<winrm_rs::WinrmClient>,
    last_used: Instant,
}

/// Pool configuration.
#[derive(Debug, Clone, Copy)]
pub struct PsrpPoolConfig {
    /// How long an idle client stays cached before eviction.
    pub max_idle: Duration,
}

impl Default for PsrpPoolConfig {
    fn default() -> Self {
        Self {
            max_idle: DEFAULT_PSRP_IDLE_TTL,
        }
    }
}

/// Cache of `WinrmClient` instances for PSRP hosts, keyed by host name.
///
/// Follows the same pattern as `WinRmPool`: `Arc<RwLock<HashMap>>` with
/// fast/cold path lookup. Reuses `crate::winrm::build_winrm_config()`
/// for the bridge → `winrm-rs` config mapping.
#[derive(Clone)]
pub struct PsrpPool {
    inner: Arc<RwLock<HashMap<String, PooledClient>>>,
    config: PsrpPoolConfig,
}

impl PsrpPool {
    /// Create a pool with default 300 s idle TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PsrpPoolConfig::default())
    }

    /// Create a pool with custom configuration.
    #[must_use]
    pub fn with_config(config: PsrpPoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Fetch or create a `PsrpConnection` for `host_name`.
    ///
    /// **Fast path**: cached `WinrmClient` still fresh — clone Arc, return.
    /// **Cold path**: `build_winrm_config()` → `WinrmClient::new()` → cache.
    ///
    /// # Errors
    ///
    /// Returns an error if auth config is invalid or client creation fails.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<PsrpConnection> {
        // Fast path: cached entry still fresh.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(host_name)
                && entry.last_used.elapsed() <= self.config.max_idle
            {
                debug!(host = %host_name, "PsrpPool hit — reusing cached WinrmClient");
                let client = Arc::clone(&entry.client);
                drop(guard);
                let mut w = self.inner.write().await;
                if let Some(entry) = w.get_mut(host_name) {
                    entry.last_used = Instant::now();
                }
                return Ok(PsrpConnection::from_parts(host_name, client));
            }
        }

        // Cold path: build new WinrmClient via build_winrm_config().
        let (winrm_config, credentials) = crate::winrm::build_winrm_config(host_config)?;
        let client = Arc::new(winrm_rs::WinrmClient::new(winrm_config, credentials)?);

        {
            let mut guard = self.inner.write().await;
            guard.insert(
                host_name.to_string(),
                PooledClient {
                    client: Arc::clone(&client),
                    last_used: Instant::now(),
                },
            );
        }

        info!(host = %host_name, "PsrpPool miss — created new WinrmClient for PSRP");
        Ok(PsrpConnection::from_parts(host_name, client))
    }

    /// Remove a cached entry (called on connection failure).
    pub async fn evict(&self, host_name: &str) {
        let mut guard = self.inner.write().await;
        if guard.remove(host_name).is_some() {
            info!(host = %host_name, "PsrpPool evicted failed client");
        }
    }

    /// Evict entries idle longer than the configured TTL.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        guard.retain(|_, entry| now.duration_since(entry.last_used) <= self.config.max_idle);
    }

    /// Close all cached entries.
    pub async fn close_all(&self) {
        let mut guard = self.inner.write().await;
        guard.clear();
        info!("Closed all PSRP pool entries");
    }

    /// Number of cached entries (for tests).
    pub async fn size(&self) -> usize {
        self.inner.read().await.len()
    }
}

impl Default for PsrpPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType, Protocol};

    fn test_host() -> HostConfig {
        HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 5986,
            user: "admin".to_string(),
            auth: AuthConfig::Password {
                password: crate::config::RedactedSecret::from("pass"),
            },
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::Windows,
            shell: None,
            retry: None,
            protocol: Protocol::default(),
            winrm_use_tls: None,
            winrm_accept_invalid_certs: None,
            winrm_operation_timeout_secs: None,
            winrm_max_envelope_size: None,
        }
    }

    #[test]
    fn test_default_config() {
        let config = PsrpPoolConfig::default();
        assert_eq!(config.max_idle, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_pool_default_empty() {
        let pool = PsrpPool::new();
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_insert_then_lookup() {
        let pool = PsrpPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        let _conn1 = pool
            .get_connection("psrp-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);

        let _conn2 = pool
            .get_connection("psrp-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_evict_removes_entry() {
        let pool = PsrpPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool
            .get_connection("psrp-host", &host, &limits)
            .await
            .unwrap();
        assert_eq!(pool.size().await, 1);
        pool.evict("psrp-host").await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_expired_entry_is_rebuilt() {
        let pool = PsrpPool::with_config(PsrpPoolConfig {
            max_idle: Duration::from_millis(1),
        });
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_close_all() {
        let pool = PsrpPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        for name in ["a", "b", "c"] {
            let _ = pool.get_connection(name, &host, &limits).await.unwrap();
        }
        assert_eq!(pool.size().await, 3);
        pool.close_all().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_cleanup_drops_stale() {
        let pool = PsrpPool::with_config(PsrpPoolConfig {
            max_idle: Duration::from_millis(10),
        });
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        pool.cleanup().await;
        assert_eq!(pool.size().await, 0);
    }
}
