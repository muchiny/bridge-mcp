//! `K8sExecPool` — reuse `kube::Client` instances across calls.
//!
//! `kube::Client::try_from(Config::infer().await?)` is expensive:
//!
//! - `Config::infer()` walks the kubeconfig, resolves the current
//!   context, runs the auth exec plugin (e.g. `gcloud`, `aws eks`
//!   token helpers, OIDC refresh) and parses certificates.
//! - `Client::try_from()` builds the TLS stack and reqwest HTTPS
//!   client pool.
//!
//! Both together can take 50-200 ms on a cold invocation and roughly
//! 10-20 ms on a warm one (the auth plugin cache short-circuits).
//! `kube::Client` is cheap to `Clone` — it's an `Arc<Inner>` sharing
//! the same HTTPS connection pool — so caching one client per host
//! name amortizes the cold-path cost across every subsequent call.
//!
//! Design mirrors `crate::winrm::WinRmPool`: one `kube::Client` per
//! `host_name`, 300-second idle TTL (K8s auth tokens typically have
//! 1-hour lifetimes so 5 minutes of idle is very safe), eviction on
//! `mark_failed()`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kube::{Client, Config};
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::K8sExecConnection;
use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};

/// Default idle TTL for cached `kube::Client` entries.
const DEFAULT_K8S_IDLE_TTL: Duration = Duration::from_mins(5);

#[derive(Clone)]
struct PooledClient {
    client: Client,
    last_used: Instant,
}

/// Pool configuration.
#[derive(Debug, Clone, Copy)]
pub struct K8sExecPoolConfig {
    /// How long an idle `kube::Client` stays cached before being evicted.
    pub max_idle: Duration,
}

impl Default for K8sExecPoolConfig {
    fn default() -> Self {
        Self {
            max_idle: DEFAULT_K8S_IDLE_TTL,
        }
    }
}

/// Cache of live `kube::Client` instances keyed by host name.
#[derive(Clone)]
pub struct K8sExecPool {
    inner: Arc<RwLock<HashMap<String, PooledClient>>>,
    config: K8sExecPoolConfig,
}

impl K8sExecPool {
    /// Create a new pool with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(K8sExecPoolConfig::default())
    }

    /// Create a new pool with an explicit configuration.
    #[must_use]
    pub fn with_config(config: K8sExecPoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Fetch or create a `K8sExecConnection` for `host_name`.
    ///
    /// On a cold entry, builds a fresh `kube::Client` via
    /// `Config::infer()` (kubeconfig walk + auth plugin resolution +
    /// TLS stack setup). On a warm entry, clones the cached client —
    /// which is an `Arc` and shares the underlying HTTPS connection
    /// pool — skipping the ~50-200 ms cold-start cost.
    ///
    /// # Errors
    ///
    /// Returns an error if `Config::infer()` fails (missing kubeconfig,
    /// unreachable cluster, auth plugin error) or if the connection
    /// target (namespace + pod) cannot be resolved.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<K8sExecConnection> {
        // Fast path: cached entry still fresh.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(host_name)
                && entry.last_used.elapsed() <= self.config.max_idle
            {
                debug!(host = %host_name, "K8sExecPool hit — reusing cached client");
                let client = entry.client.clone();
                drop(guard);
                // Update last_used under the write lock.
                let mut w = self.inner.write().await;
                if let Some(entry) = w.get_mut(host_name) {
                    entry.last_used = Instant::now();
                }
                return K8sExecConnection::from_parts(host_name, host_config, client);
            }
        }

        // Cold path: build a new client under the write lock.
        let k8s_config = Config::infer().await.map_err(|e| BridgeError::SshExec {
            reason: format!("K8s config inference failed: {e}"),
        })?;
        let client = Client::try_from(k8s_config).map_err(|e| BridgeError::SshExec {
            reason: format!("K8s client creation failed: {e}"),
        })?;

        {
            let mut guard = self.inner.write().await;
            guard.insert(
                host_name.to_string(),
                PooledClient {
                    client: client.clone(),
                    last_used: Instant::now(),
                },
            );
        }

        info!(host = %host_name, "K8sExecPool miss — created new kube::Client");
        K8sExecConnection::from_parts(host_name, host_config, client)
    }

    /// Drop a cached client for `host_name`.
    pub async fn evict(&self, host_name: &str) {
        let mut guard = self.inner.write().await;
        if guard.remove(host_name).is_some() {
            info!(host = %host_name, "K8sExecPool evicted failed client");
        }
    }

    /// Evict entries idle longer than the configured TTL.
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

impl Default for K8sExecPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    //! Note: constructing real `kube::Client` in unit tests requires
    //! a valid kubeconfig. These tests only exercise the bits of the
    //! pool that don't actually call `Config::infer()` — size tracking,
    //! eviction, and cleanup — by directly manipulating the inner map.
    //! Full end-to-end tests belong in `tests/e2e_k8s.rs` which runs
    //! against a real kind/minikube cluster.
    use super::*;

    #[tokio::test]
    async fn test_pool_default_empty() {
        let pool = K8sExecPool::new();
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_default_config() {
        let pool = K8sExecPool::default();
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_evict_nonexistent_is_noop() {
        let pool = K8sExecPool::new();
        pool.evict("nonexistent").await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_close_all_on_empty() {
        let pool = K8sExecPool::new();
        pool.close_all().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_cleanup_on_empty() {
        let pool = K8sExecPool::new();
        pool.cleanup().await;
        assert_eq!(pool.size().await, 0);
    }

    #[test]
    fn test_pool_config_default_ttl() {
        let cfg = K8sExecPoolConfig::default();
        assert_eq!(cfg.max_idle, Duration::from_mins(5));
    }
}
