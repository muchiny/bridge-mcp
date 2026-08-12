//! Per-session bundled state.
//!
//! Audit 2026-05-09 (FIND-033/034/036/037) moved four fields off the
//! shared `McpServer` and into per-session storage allocated in
//! `serve_session()`. Together with the prior fixes from Vuln 8, Vuln 9,
//! and FIND-038, that adds up to seven Arc/handle parameters threaded
//! through `route_incoming_message → handle_request_with_cancel →
//! handle_tools_call → create_tool_context`. To avoid the parameter
//! explosion (and per the FIND-038 quality review's standing
//! recommendation), this module bundles them into a single
//! [`SessionContext`].
//!
//! Lifetime: a fresh [`SessionContext`] is allocated at the top of
//! `McpServer::serve_session()` and shared by clone (cheap — every
//! field is `Arc`-wrapped) into spawned per-request tasks. Each session
//! owns an independent bundle, so cross-session leakage is impossible
//! by construction.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use tokio::sync::{RwLock, mpsc};

use super::pending_requests::PendingRequests;
use super::protocol::{LogLevel, RootEntry, WriterMessage};
use super::session_capabilities::SessionCapabilities;

/// All per-session state bundled into one cloneable handle.
///
/// Every field is an `Arc`/handle so `Clone` is cheap. Spawned per-request
/// tasks clone the whole bundle to avoid threading 7+ individual
/// parameters through the dispatch chain.
#[derive(Clone)]
pub struct SessionContext {
    /// Per-session pending-requests map (Vuln 8).
    pub pending: Arc<PendingRequests>,
    /// Per-session client capability flags (Vuln 9).
    pub caps: Arc<SessionCapabilities>,
    /// Per-session active-requests map for MCP cancellation (FIND-038).
    pub active_requests: super::server::ActiveRequests,
    /// Per-session writer channel for server-initiated messages
    /// (notifications, requests). FIND-034.
    pub notification_tx: mpsc::Sender<WriterMessage>,
    /// Per-session runtime override for `max_output_chars`. Written by
    /// `handle_initialize` based on this client's `client_overrides`
    /// profile and read by `create_tool_context`. FIND-033.
    pub runtime_max_output: Arc<RwLock<Option<usize>>>,
    /// Per-session resource subscription map (URI -> subscription IDs).
    /// FIND-036.
    pub resource_subs: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Per-session client-declared workspace roots. Written by
    /// `fetch_roots` after `notifications/initialized`. FIND-037.
    pub roots: Arc<RwLock<Vec<RootEntry>>>,
    /// Per-session log-level threshold for `notifications/message`.
    /// Updated by `notifications/setLevel` from THIS session, read by
    /// the per-session `McpLogger`. FIND-035: previously a global
    /// `Arc<AtomicU8>` on `McpServer`, so client B's setLevel could
    /// mute client A's notifications.
    pub log_level: Arc<AtomicU8>,
}

impl SessionContext {
    /// Allocate a fresh per-session bundle, given the writer channel
    /// returned by `serve_session()`'s `mpsc::channel`.
    #[must_use]
    pub fn new(notification_tx: mpsc::Sender<WriterMessage>) -> Self {
        Self {
            pending: Arc::new(PendingRequests::new()),
            caps: Arc::new(SessionCapabilities::new()),
            active_requests: super::server::ActiveRequests::new(),
            notification_tx,
            runtime_max_output: Arc::new(RwLock::new(None)),
            resource_subs: Arc::new(RwLock::new(HashMap::new())),
            roots: Arc::new(RwLock::new(Vec::new())),
            log_level: Arc::new(AtomicU8::new(LogLevel::Warning.severity())),
        }
    }
}

/// Server-wide registry of live session writer channels for **fanout**
/// (broadcast) notifications.
///
/// FIND-034 (audit 2026-05-09): the previous topology had a single
/// last-writer-wins `notification_tx` slot on `McpServer`. The config
/// watcher (and any other server-wide event source) used that slot to
/// emit `notifications/tools/list_changed` and
/// `notifications/resources/list_changed`, so the broadcast routed to
/// only ONE session — whichever connected most recently.
///
/// The fix splits the topology in two:
/// - **Per-session direct sender** lives on [`SessionContext::notification_tx`]
///   and is used for messages addressed to one specific client (progress,
///   elicitation, sampling, per-session logging).
/// - **Server-wide fanout registry** ([`NotificationFanout`]) tracks every
///   live session's tx and is used for broadcasts that legitimately go to
///   ALL connected clients (config-reload `list_changed` events).
///
/// `serve_session()` registers its tx on entry and removes it on exit.
/// `Drop` of `FanoutGuard` enforces removal even when a session task
/// panics so dead senders never accumulate.
#[derive(Default, Clone)]
pub struct NotificationFanout {
    senders: Arc<std::sync::Mutex<Vec<mpsc::Sender<WriterMessage>>>>,
}

impl NotificationFanout {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session's tx. The returned guard removes the entry
    /// from the fanout when dropped (session ends or panics). Tolerates
    /// a poisoned mutex silently — a stale entry is preferable to a
    /// crash on the dispatch path.
    #[must_use]
    pub fn register(&self, tx: mpsc::Sender<WriterMessage>) -> FanoutGuard {
        if let Ok(mut v) = self.senders.lock() {
            v.push(tx.clone());
        }
        FanoutGuard {
            owner: Arc::clone(&self.senders),
            tx,
        }
    }

    /// Best-effort fanout: send `msg` to every live session.
    ///
    /// Uses `try_send` so a slow consumer never blocks the broadcaster;
    /// dropped messages on a full per-session buffer are acceptable
    /// because list-changed notifications are state-derived and the
    /// client refreshes on demand. Channel-closed errors prune the
    /// dead sender from the registry.
    ///
    /// `msg` is taken by reference and `clone()`d once per live
    /// session — `WriterMessage` is `Clone` specifically to support
    /// this fanout topology.
    pub fn broadcast(&self, msg: &WriterMessage) {
        let snapshot: Vec<mpsc::Sender<WriterMessage>> = match self.senders.lock() {
            Ok(v) => v.clone(),
            Err(_) => return,
        };
        let mut dead = Vec::new();
        for tx in &snapshot {
            if let Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) = tx.try_send(msg.clone())
            {
                dead.push(tx.clone());
            }
        }
        if !dead.is_empty()
            && let Ok(mut v) = self.senders.lock()
        {
            v.retain(|tx| !dead.iter().any(|d| d.same_channel(tx)));
        }
    }

    /// Test helper: number of live registered sessions.
    #[doc(hidden)]
    #[must_use]
    pub fn live_session_count(&self) -> usize {
        self.senders.lock().map_or(0, |v| v.len())
    }
}

/// RAII guard returned from [`NotificationFanout::register`]. Drops the
/// associated tx out of the registry on drop so dead sessions do not
/// leak senders.
pub struct FanoutGuard {
    owner: Arc<std::sync::Mutex<Vec<mpsc::Sender<WriterMessage>>>>,
    tx: mpsc::Sender<WriterMessage>,
}

impl Drop for FanoutGuard {
    fn drop(&mut self) {
        if let Ok(mut v) = self.owner.lock() {
            // Same-channel comparison ensures we drop ONLY our own entry,
            // even if multiple guards collide on duplicate registrations.
            if let Some(pos) = v.iter().position(|tx| tx.same_channel(&self.tx)) {
                v.swap_remove(pos);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::protocol::{JsonRpcNotification, LogLevel};

    fn dummy_writer_tx() -> mpsc::Sender<WriterMessage> {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        tx
    }

    #[tokio::test]
    async fn session_context_new_initializes_default_state() {
        let tx = dummy_writer_tx();
        let ctx = SessionContext::new(tx);

        // Default log level matches Warning severity (FIND-035 default).
        assert_eq!(
            ctx.log_level.load(std::sync::atomic::Ordering::Relaxed),
            LogLevel::Warning.severity()
        );

        // All map/list state empty on construction.
        assert!(ctx.runtime_max_output.read().await.is_none());
        assert!(ctx.resource_subs.read().await.is_empty());
        assert!(ctx.roots.read().await.is_empty());
    }

    #[tokio::test]
    async fn session_context_clone_shares_inner_state() {
        let tx = dummy_writer_tx();
        let a = SessionContext::new(tx);
        let b = a.clone();

        // Mutating Arc-wrapped state through clone B is visible from A.
        *b.runtime_max_output.write().await = Some(4096);
        assert_eq!(*a.runtime_max_output.read().await, Some(4096));
    }

    #[test]
    fn fanout_new_is_empty() {
        let f = NotificationFanout::new();
        assert_eq!(f.live_session_count(), 0);
    }

    #[test]
    fn fanout_register_increments_live_count() {
        let f = NotificationFanout::new();
        let (tx1, _rx1) = mpsc::channel::<WriterMessage>(4);
        let (tx2, _rx2) = mpsc::channel::<WriterMessage>(4);
        let g1 = f.register(tx1);
        let g2 = f.register(tx2);
        assert_eq!(f.live_session_count(), 2);
        drop(g1);
        drop(g2);
    }

    #[test]
    fn fanout_guard_drop_removes_entry() {
        let f = NotificationFanout::new();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(4);
        {
            let _g = f.register(tx);
            assert_eq!(f.live_session_count(), 1);
        }
        assert_eq!(f.live_session_count(), 0);
    }

    #[test]
    fn fanout_guards_drop_only_their_own_entry() {
        let f = NotificationFanout::new();
        let (tx1, _rx1) = mpsc::channel::<WriterMessage>(4);
        let (tx2, _rx2) = mpsc::channel::<WriterMessage>(4);
        let g1 = f.register(tx1);
        let g2 = f.register(tx2);
        assert_eq!(f.live_session_count(), 2);
        drop(g1);
        assert_eq!(f.live_session_count(), 1);
        drop(g2);
        assert_eq!(f.live_session_count(), 0);
    }

    #[tokio::test]
    async fn fanout_broadcast_delivers_to_every_session() {
        let f = NotificationFanout::new();
        let (tx1, mut rx1) = mpsc::channel::<WriterMessage>(4);
        let (tx2, mut rx2) = mpsc::channel::<WriterMessage>(4);
        let _g1 = f.register(tx1);
        let _g2 = f.register(tx2);

        let msg = WriterMessage::Notification(JsonRpcNotification::tools_list_changed());
        f.broadcast(&msg);

        // Both sessions receive a copy of the broadcast.
        for (idx, rx) in [&mut rx1, &mut rx2].iter_mut().enumerate() {
            match rx.try_recv() {
                Ok(WriterMessage::Notification(n)) => {
                    assert_eq!(n.method, "notifications/tools/list_changed");
                }
                Ok(_) => panic!("session {idx}: expected Notification variant"),
                Err(e) => panic!("session {idx}: try_recv failed: {e:?}"),
            }
        }
    }

    #[test]
    fn fanout_broadcast_with_no_senders_is_noop() {
        let f = NotificationFanout::new();
        // Must not panic / must not deadlock.
        f.broadcast(&WriterMessage::Notification(
            JsonRpcNotification::tools_list_changed(),
        ));
        assert_eq!(f.live_session_count(), 0);
    }

    #[test]
    fn fanout_broadcast_prunes_closed_senders() {
        let f = NotificationFanout::new();
        let (tx_dead, rx_dead) = mpsc::channel::<WriterMessage>(4);
        let (tx_live, _rx_live) = mpsc::channel::<WriterMessage>(4);
        let _g_dead = f.register(tx_dead);
        let _g_live = f.register(tx_live);
        assert_eq!(f.live_session_count(), 2);

        // Close the first channel by dropping its receiver.
        drop(rx_dead);

        f.broadcast(&WriterMessage::Notification(
            JsonRpcNotification::tools_list_changed(),
        ));

        // Dead sender pruned, live sender remains.
        assert_eq!(f.live_session_count(), 1);
    }
}
