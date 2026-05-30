//! `WinRmPool` — cache `winrm_rs::WinrmClient` instances per host.
//!
//! `WinRM` is request/response HTTP with no long-lived session, but
//! `WinrmClient` internally holds a `reqwest::Client` with TLS state
//! and auth context (`NTLMv2` session tokens, etc.). Caching the client
//! avoids repeating TLS handshakes and auth negotiations on every call.
//!
//! 120 s idle TTL matches `WinRM` server idle timeouts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info};

use super::{WinRmConnection, build_winrm_config};
use crate::config::{HostConfig, LimitsConfig};
use crate::error::Result;

/// Default idle TTL for cached `WinrmClient` entries.
const DEFAULT_WINRM_IDLE_TTL: Duration = Duration::from_secs(120);

/// A cached entry: one `WinrmClient` + last-used timestamp.
struct PooledClient {
    client: Arc<winrm_rs::WinrmClient>,
    last_used: Instant,
}

/// Pool configuration.
#[derive(Debug, Clone, Copy)]
pub struct WinRmPoolConfig {
    /// How long an idle client stays cached before being evicted.
    pub max_idle: Duration,
}

impl Default for WinRmPoolConfig {
    fn default() -> Self {
        Self {
            max_idle: DEFAULT_WINRM_IDLE_TTL,
        }
    }
}

/// Cache of `winrm_rs::WinrmClient` instances keyed by host name.
///
/// The pool is cheap to clone (`Arc` internally) and safe to share
/// across tasks — all mutation happens under an `RwLock`.
#[derive(Clone)]
pub struct WinRmPool {
    inner: Arc<RwLock<HashMap<String, PooledClient>>>,
    config: WinRmPoolConfig,
}

impl WinRmPool {
    /// Create a new pool with default configuration (120 s idle TTL).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(WinRmPoolConfig::default())
    }

    /// Create a new pool with an explicit configuration.
    #[must_use]
    pub fn with_config(config: WinRmPoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Fetch or create a `WinRmConnection` for `host_name`.
    ///
    /// **Fast path**: if a cached `WinrmClient` exists and is fresh,
    /// wraps it in a new `WinRmConnection` (zero network cost).
    ///
    /// **Cold path**: calls `build_winrm_config()` to map bridge config
    /// to `winrm-rs` types, creates a new `WinrmClient`, caches it,
    /// and returns the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if auth config is invalid or `WinrmClient` creation fails.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<WinRmConnection> {
        // Fast path: cached entry still fresh.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(host_name)
                && entry.last_used.elapsed() <= self.config.max_idle
            {
                debug!(host = %host_name, "WinRmPool hit — reusing cached WinrmClient");
                let client = Arc::clone(&entry.client);
                drop(guard);
                // Update last_used under write lock.
                let mut w = self.inner.write().await;
                if let Some(entry) = w.get_mut(host_name) {
                    entry.last_used = Instant::now();
                }
                return Ok(WinRmConnection::from_parts(host_name, client));
            }
        }

        // Cold path: build new WinrmClient via build_winrm_config().
        let (winrm_config, credentials) = build_winrm_config(host_config)?;
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

        info!(host = %host_name, "WinRmPool miss — created new WinrmClient");
        Ok(WinRmConnection::from_parts(host_name, client))
    }

    /// Drop a cached client for `host_name` (called on connection failure).
    pub async fn evict(&self, host_name: &str) {
        let mut guard = self.inner.write().await;
        if guard.remove(host_name).is_some() {
            info!(host = %host_name, "WinRmPool evicted failed client");
        }
    }

    /// Evict entries that have been idle longer than the configured TTL.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        guard.retain(|_, entry| now.duration_since(entry.last_used) <= self.config.max_idle);
    }

    /// Current number of cached entries (for tests / stats).
    pub async fn size(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Evict every entry. Called on server shutdown.
    pub async fn close_all(&self) {
        let mut guard = self.inner.write().await;
        guard.clear();
    }
}

impl Default for WinRmPool {
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
            protocol: Protocol::WinRm,
            winrm_use_tls: None,
            winrm_accept_invalid_certs: None,
            winrm_operation_timeout_secs: None,
            winrm_max_envelope_size: None,
        }
    }

    #[tokio::test]
    async fn test_pool_default_empty() {
        let pool = WinRmPool::new();
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_insert_then_lookup() {
        let pool = WinRmPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        // First call: cold, builds a WinrmClient.
        let _conn1 = pool
            .get_connection("my-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);

        // Second call: should reuse the cached client.
        let _conn2 = pool
            .get_connection("my-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_evict_removes_entry() {
        let pool = WinRmPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool
            .get_connection("my-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);

        pool.evict("my-host").await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_expired_entry_is_rebuilt() {
        let pool = WinRmPool::with_config(WinRmPoolConfig {
            max_idle: Duration::from_millis(1),
        });
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        assert_eq!(pool.size().await, 1);

        // Force expiry
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_close_all() {
        let pool = WinRmPool::new();
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
        let pool = WinRmPool::with_config(WinRmPoolConfig {
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
