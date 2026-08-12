//! Tunnel Manager Use Case
//!
//! Manages the lifecycle of SSH port forwarding tunnels.
//! Each tunnel has an ID and metadata, plus an abort handle
//! to stop the forwarding task.

use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::error::{BridgeError, Result};

/// Direction of the port forwarding tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelDirection {
    /// Local port forwarding: local:port -> remote:port
    Local,
    /// Remote port forwarding: remote:port -> local:port
    Remote,
}

/// Metadata about an active tunnel
#[derive(Debug, Clone, Serialize)]
pub struct TunnelInfo {
    pub id: String,
    pub host: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub direction: TunnelDirection,
    #[serde(skip)]
    pub created_at: Instant,
    pub age_seconds: u64,
}

/// Internal state for a tunnel (not exposed)
struct TunnelEntry {
    info: TunnelInfo,
    handle: JoinHandle<()>,
}

/// Manages active SSH tunnels
pub struct TunnelManager {
    tunnels: Mutex<HashMap<String, TunnelEntry>>,
    max_tunnels: usize,
}

impl TunnelManager {
    #[must_use]
    pub fn new(max_tunnels: usize) -> Self {
        Self {
            tunnels: Mutex::new(HashMap::new()),
            max_tunnels,
        }
    }

    /// Register a new tunnel with the given info and forwarding task handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of tunnels is reached.
    pub async fn register(&self, info: TunnelInfo, handle: JoinHandle<()>) -> Result<()> {
        let mut tunnels = self.tunnels.lock().await;

        if tunnels.len() >= self.max_tunnels {
            return Err(BridgeError::Tunnel {
                reason: format!("Maximum number of tunnels reached ({})", self.max_tunnels),
            });
        }

        tunnels.insert(info.id.clone(), TunnelEntry { info, handle });
        Ok(())
    }

    /// List all active tunnels with updated age.
    pub async fn list(&self) -> Vec<TunnelInfo> {
        let tunnels = self.tunnels.lock().await;
        tunnels
            .values()
            .map(|entry| {
                let mut info = entry.info.clone();
                info.age_seconds = info.created_at.elapsed().as_secs();
                info
            })
            .collect()
    }

    /// Close a tunnel by ID and abort its forwarding task.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel ID is not found.
    pub async fn close(&self, tunnel_id: &str) -> Result<TunnelInfo> {
        let mut tunnels = self.tunnels.lock().await;
        let entry = tunnels
            .remove(tunnel_id)
            .ok_or_else(|| BridgeError::Tunnel {
                reason: format!("Tunnel not found: {tunnel_id}"),
            })?;

        entry.handle.abort();
        let mut info = entry.info;
        info.age_seconds = info.created_at.elapsed().as_secs();
        Ok(info)
    }

    /// Close all tunnels (used during shutdown).
    pub async fn close_all(&self) {
        let mut tunnels = self.tunnels.lock().await;
        for (_, entry) in tunnels.drain() {
            entry.handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(id: &str) -> TunnelInfo {
        TunnelInfo {
            id: id.to_string(),
            host: "test-server".to_string(),
            local_port: 8080,
            remote_host: "localhost".to_string(),
            remote_port: 80,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        }
    }

    #[tokio::test]
    async fn test_register_and_list() {
        let manager = TunnelManager::new(10);
        let info = make_info("t1");
        let handle = tokio::spawn(async {});

        manager.register(info, handle).await.unwrap();
        let list = manager.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "t1");
    }

    #[tokio::test]
    async fn test_close_tunnel() {
        let manager = TunnelManager::new(10);
        let info = make_info("t1");
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_mins(1)).await;
        });

        manager.register(info, handle).await.unwrap();
        let closed = manager.close("t1").await.unwrap();
        assert_eq!(closed.id, "t1");
        assert!(manager.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_close_nonexistent_tunnel() {
        let manager = TunnelManager::new(10);
        let result = manager.close("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_max_tunnels_exceeded() {
        let manager = TunnelManager::new(1);
        let info1 = make_info("t1");
        let handle1 = tokio::spawn(async {});
        manager.register(info1, handle1).await.unwrap();

        let info2 = make_info("t2");
        let handle2 = tokio::spawn(async {});
        let result = manager.register(info2, handle2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_all() {
        let manager = TunnelManager::new(10);
        for i in 0..3 {
            let info = make_info(&format!("t{i}"));
            let handle = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_mins(1)).await;
            });
            manager.register(info, handle).await.unwrap();
        }

        assert_eq!(manager.list().await.len(), 3);
        manager.close_all().await;
        assert!(manager.list().await.is_empty());
    }

    #[test]
    fn test_tunnel_direction_serialization() {
        let local = serde_json::to_string(&TunnelDirection::Local).unwrap();
        let remote = serde_json::to_string(&TunnelDirection::Remote).unwrap();
        assert_eq!(local, "\"local\"");
        assert_eq!(remote, "\"remote\"");
    }

    // ============== State Management ==============

    #[tokio::test]
    async fn test_register_duplicate_id_overwrites() {
        let manager = TunnelManager::new(10);
        let info1 = make_info("t1");
        let handle1 = tokio::spawn(async {});
        manager.register(info1, handle1).await.unwrap();

        let info2 = make_info("t1");
        let handle2 = tokio::spawn(async {});
        manager.register(info2, handle2).await.unwrap();

        let list = manager.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "t1");
    }

    #[tokio::test]
    async fn test_register_max_zero_rejects() {
        let manager = TunnelManager::new(0);
        let info = make_info("t1");
        let handle = tokio::spawn(async {});
        let result = manager.register(info, handle).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_exactly_at_max() {
        let manager = TunnelManager::new(3);
        for i in 0..3 {
            let info = make_info(&format!("t{i}"));
            let handle = tokio::spawn(async {});
            manager.register(info, handle).await.unwrap();
        }
        assert_eq!(manager.list().await.len(), 3);

        let info_extra = make_info("t3");
        let handle_extra = tokio::spawn(async {});
        let result = manager.register(info_extra, handle_extra).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_then_reuse_id() {
        let manager = TunnelManager::new(10);
        let info1 = make_info("t1");
        let handle1 = tokio::spawn(async {});
        manager.register(info1, handle1).await.unwrap();

        manager.close("t1").await.unwrap();

        let info2 = make_info("t1");
        let handle2 = tokio::spawn(async {});
        manager.register(info2, handle2).await.unwrap();

        let list = manager.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "t1");
    }

    #[tokio::test]
    async fn test_list_empty_on_new_manager() {
        let manager = TunnelManager::new(10);
        assert!(manager.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_close_all_on_empty_manager() {
        let manager = TunnelManager::new(10);
        manager.close_all().await;
        assert!(manager.list().await.is_empty());
    }

    // ============== Field Preservation ==============

    #[tokio::test]
    async fn test_list_preserves_tunnel_info_fields() {
        let manager = TunnelManager::new(10);
        let info = TunnelInfo {
            id: "test-id".to_string(),
            host: "prod-server".to_string(),
            local_port: 9090,
            remote_host: "db.internal".to_string(),
            remote_port: 5432,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };
        let handle = tokio::spawn(async {});
        manager.register(info, handle).await.unwrap();

        let list = manager.list().await;
        assert_eq!(list[0].id, "test-id");
        assert_eq!(list[0].host, "prod-server");
        assert_eq!(list[0].local_port, 9090);
        assert_eq!(list[0].remote_host, "db.internal");
        assert_eq!(list[0].remote_port, 5432);
        assert_eq!(list[0].direction, TunnelDirection::Local);
    }

    #[tokio::test]
    async fn test_close_returns_correct_info_fields() {
        let manager = TunnelManager::new(10);
        let info = TunnelInfo {
            id: "close-test".to_string(),
            host: "web-server".to_string(),
            local_port: 3000,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8080,
            direction: TunnelDirection::Remote,
            created_at: Instant::now(),
            age_seconds: 0,
        };
        let handle = tokio::spawn(async {});
        manager.register(info, handle).await.unwrap();

        let closed = manager.close("close-test").await.unwrap();
        assert_eq!(closed.id, "close-test");
        assert_eq!(closed.host, "web-server");
        assert_eq!(closed.local_port, 3000);
        assert_eq!(closed.direction, TunnelDirection::Remote);
    }

    #[tokio::test]
    async fn test_tunnel_remote_direction() {
        let manager = TunnelManager::new(10);
        let mut info = make_info("remote-t");
        info.direction = TunnelDirection::Remote;
        let handle = tokio::spawn(async {});
        manager.register(info, handle).await.unwrap();

        let list = manager.list().await;
        assert_eq!(list[0].direction, TunnelDirection::Remote);
    }

    #[tokio::test]
    async fn test_age_seconds_updates() {
        let manager = TunnelManager::new(10);
        let info = make_info("age-test");
        let handle = tokio::spawn(async {});
        manager.register(info, handle).await.unwrap();

        // age_seconds is recomputed on list()
        let list = manager.list().await;
        assert!(list[0].age_seconds < 5); // should be near 0
    }

    // ============== Multiple Tunnels ==============

    #[tokio::test]
    async fn test_list_multiple_tunnels() {
        let manager = TunnelManager::new(10);
        for i in 0..3 {
            let info = make_info(&format!("m{i}"));
            let handle = tokio::spawn(async {});
            manager.register(info, handle).await.unwrap();
        }
        let list = manager.list().await;
        assert_eq!(list.len(), 3);
        let ids: Vec<&str> = list.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"m0"));
        assert!(ids.contains(&"m1"));
        assert!(ids.contains(&"m2"));
    }

    #[tokio::test]
    async fn test_close_one_of_many() {
        let manager = TunnelManager::new(10);
        for i in 0..3 {
            let info = make_info(&format!("c{i}"));
            let handle = tokio::spawn(async {});
            manager.register(info, handle).await.unwrap();
        }
        manager.close("c1").await.unwrap();
        let list = manager.list().await;
        assert_eq!(list.len(), 2);
        let ids: Vec<&str> = list.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"c0"));
        assert!(ids.contains(&"c2"));
        assert!(!ids.contains(&"c1"));
    }

    #[tokio::test]
    async fn test_register_close_cycle_repeated() {
        let manager = TunnelManager::new(10);
        for i in 0..3 {
            let info = make_info(&format!("cycle{i}"));
            let handle = tokio::spawn(async {});
            manager.register(info, handle).await.unwrap();
            manager.close(&format!("cycle{i}")).await.unwrap();
        }
        let info = make_info("final");
        let handle = tokio::spawn(async {});
        manager.register(info, handle).await.unwrap();
        let list = manager.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "final");
    }

    #[tokio::test]
    async fn test_multiple_close_all_calls() {
        let manager = TunnelManager::new(10);
        for i in 0..2 {
            let info = make_info(&format!("d{i}"));
            let handle = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_mins(1)).await;
            });
            manager.register(info, handle).await.unwrap();
        }
        manager.close_all().await;
        manager.close_all().await; // second call should not panic
        assert!(manager.list().await.is_empty());
    }

    // ============== Error Messages ==============

    #[tokio::test]
    async fn test_close_nonexistent_error_contains_id() {
        let manager = TunnelManager::new(10);
        let result = manager.close("missing-tunnel-xyz").await;
        match result.unwrap_err() {
            BridgeError::Tunnel { reason } => {
                assert!(reason.contains("missing-tunnel-xyz"));
            }
            other => panic!("Expected BridgeError::Tunnel, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_register_exceeded_error_contains_max() {
        let manager = TunnelManager::new(2);
        for i in 0..2 {
            let info = make_info(&format!("e{i}"));
            let handle = tokio::spawn(async {});
            manager.register(info, handle).await.unwrap();
        }
        let info = make_info("e2");
        let handle = tokio::spawn(async {});
        let result = manager.register(info, handle).await;
        match result.unwrap_err() {
            BridgeError::Tunnel { reason } => {
                assert!(reason.contains('2'));
            }
            other => panic!("Expected BridgeError::Tunnel, got: {other:?}"),
        }
    }

    // ============== Serialization ==============

    #[test]
    fn test_tunnel_info_serialization_skips_created_at() {
        let info = make_info("serial-test");
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("created_at"));
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"host\""));
        assert!(json.contains("\"direction\":\"local\""));
    }
}
