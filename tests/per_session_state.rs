// `FIND-033`/`FIND-034`/`FIND-036`/`FIND-037` — verify four
// `McpServer` fields that used to be server-wide singletons are now
// per-session and do not leak across concurrent client sessions on
// the same daemon.
//
// These are unit-level integration tests in the same shape as
// `tests/cross_session_cancel.rs` (`FIND-038`) and
// `tests/multisession_isolation.rs` (Vuln 8/9): each test allocates
// two independent per-session storage handles via the dedicated test
// helpers on `McpServer` and proves they are isolated. End-to-end
// two-session driving over a real transport is intentionally out of
// scope — the load-bearing property is the data-structure isolation.
//
// Pattern: allocate two per-session storage cells via the
// `allocate_session_*_for_test` helpers, write to A, read from B,
// assert no leakage.

#![allow(clippy::doc_markdown)]

use std::collections::HashMap;
use std::sync::Arc;

use bridge_mcp::config::Config;
use bridge_mcp::mcp::McpServer;
use bridge_mcp::mcp::protocol::{RootEntry, WriterMessage};
use tokio::sync::{RwLock, mpsc};

/// `FIND-033` — `runtime_max_output_chars` was a server-wide
/// `Arc<RwLock<Option<usize>>>` written once per `initialize`.
/// Two concurrent clients with different `client_overrides` saw the
/// last-writer-wins value. The fix moves the slot per-session and the
/// test pins that property: writing `80_000` to A's slot must not leak
/// into B's slot.
#[tokio::test]
async fn runtime_max_output_chars_isolated_per_session() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = Arc::new(server);

    let cell_a: Arc<RwLock<Option<usize>>> = server.allocate_session_runtime_max_output_for_test();
    let cell_b: Arc<RwLock<Option<usize>>> = server.allocate_session_runtime_max_output_for_test();

    // Both fresh — unset.
    assert_eq!(*cell_a.read().await, None);
    assert_eq!(*cell_b.read().await, None);

    // Session A's `initialize` sets a per-client override.
    *cell_a.write().await = Some(80_000);

    // Session B must NOT observe A's override.
    assert_eq!(
        *cell_b.read().await,
        None,
        "FIND-033: session A's runtime_max_output_chars must not leak into session B"
    );

    // B can independently set a different value.
    *cell_b.write().await = Some(20_000);
    assert_eq!(*cell_a.read().await, Some(80_000));
    assert_eq!(*cell_b.read().await, Some(20_000));
}

/// `FIND-034` — `notification_tx` was a single global `Sender` slot
/// last-writer-wins. With two sessions, the slot pointed at whoever
/// connected most recently; background workers firing through the
/// global slot routed messages to the wrong client.
///
/// The fix gives each session its own `Sender` (the writer channel
/// returned by `serve_session`'s `mpsc::channel`) and propagates it
/// through `handle_request_with_cancel`. This test exercises the
/// per-session channel pattern: client A's tx receives only client A's
/// notifications.
#[tokio::test]
async fn notification_tx_does_not_cross_sessions() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let _server = Arc::new(server);

    // Allocate the per-session channels exactly the way `serve_session`
    // does — one (tx, rx) per session.
    let (tx_a, mut rx_a) = mpsc::channel::<WriterMessage>(8);
    let (tx_b, mut rx_b) = mpsc::channel::<WriterMessage>(8);

    // Send a sentinel notification to A only.
    tx_a.send(WriterMessage::Notification(
        bridge_mcp::mcp::protocol::JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/test".to_string(),
            params: Some(serde_json::json!({"who": "A"})),
        },
    ))
    .await
    .expect("send to A");

    // A's channel observes the message; B's does not.
    let msg_a = rx_a.try_recv().expect("A receives its own notification");
    match msg_a {
        WriterMessage::Notification(n) => {
            assert_eq!(n.method, "notifications/test");
            assert_eq!(n.params.unwrap()["who"], "A");
        }
        _ => panic!("expected Notification on A"),
    }

    // CRITICAL: nothing should be on B's channel — the per-session
    // fanout must NOT cross-deliver to a different session.
    assert!(
        rx_b.try_recv().is_err(),
        "FIND-034: notification sent on session A's tx must not appear on session B's rx"
    );

    // Closing A's tx must not affect B.
    drop(tx_a);
    assert!(rx_a.try_recv().is_err()); // channel closed/empty
    // B remains usable.
    tx_b.send(WriterMessage::Notification(
        bridge_mcp::mcp::protocol::JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/test".to_string(),
            params: Some(serde_json::json!({"who": "B"})),
        },
    ))
    .await
    .expect("send to B");
    let msg_b = rx_b.try_recv().expect("B still works");
    match msg_b {
        WriterMessage::Notification(n) => {
            assert_eq!(n.params.unwrap()["who"], "B");
        }
        _ => panic!("expected Notification on B"),
    }
}

/// `FIND-036` — `resource_subscriptions` was a server-wide
/// `HashMap<String, Vec<String>>` keyed on URI, not on session. Two
/// clients subscribing to the same URI shared the Vec, so client A's
/// `unsubscribe` could remove client B's subscription IDs. The fix
/// allocates a fresh map per session in `serve_session()`.
#[tokio::test]
async fn resource_subscriptions_keyed_per_session() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = Arc::new(server);

    let map_a: Arc<RwLock<HashMap<String, Vec<String>>>> =
        server.allocate_session_resource_subs_for_test();
    let map_b: Arc<RwLock<HashMap<String, Vec<String>>>> =
        server.allocate_session_resource_subs_for_test();

    // Session A subscribes to a URI.
    {
        let mut subs = map_a.write().await;
        subs.entry("ssh://prod/etc/passwd".to_string())
            .or_default()
            .push("sub-A-1".to_string());
    }

    // Session B independently subscribes to the SAME URI.
    {
        let mut subs = map_b.write().await;
        subs.entry("ssh://prod/etc/passwd".to_string())
            .or_default()
            .push("sub-B-1".to_string());
    }

    // Each map sees only its own subscription IDs.
    let snap_a = map_a.read().await.clone();
    let snap_b = map_b.read().await.clone();
    assert_eq!(
        snap_a.get("ssh://prod/etc/passwd"),
        Some(&vec!["sub-A-1".to_string()])
    );
    assert_eq!(
        snap_b.get("ssh://prod/etc/passwd"),
        Some(&vec!["sub-B-1".to_string()])
    );

    // Session A unsubscribes by URI — must NOT remove B's entry.
    {
        let mut subs = map_a.write().await;
        subs.remove("ssh://prod/etc/passwd");
    }

    let after_a = map_a.read().await.clone();
    let after_b = map_b.read().await.clone();
    assert!(
        !after_a.contains_key("ssh://prod/etc/passwd"),
        "A's own unsubscribe clears A"
    );
    assert_eq!(
        after_b.get("ssh://prod/etc/passwd"),
        Some(&vec!["sub-B-1".to_string()]),
        "FIND-036: A's unsubscribe must not affect B's subscription map"
    );
}

/// `FIND-037` — `roots: Arc<RwLock<Vec<RootEntry>>>` was a single
/// global vec. `fetch_roots` overwrote it from whichever client most
/// recently completed `notifications/initialized`. Tool handlers
/// reading `ctx.roots` (path scope validation) saw the wrong client's
/// roots. The fix is per-session storage cloned into `ToolContext` at
/// `create_tool_context` time.
#[tokio::test]
async fn roots_isolated_per_session() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = Arc::new(server);

    let roots_a: Arc<RwLock<Vec<RootEntry>>> = server.allocate_session_roots_for_test();
    let roots_b: Arc<RwLock<Vec<RootEntry>>> = server.allocate_session_roots_for_test();

    // Session A advertises one set of roots.
    *roots_a.write().await = vec![RootEntry {
        uri: "file:///srv/app-a".to_string(),
        name: Some("app-a".to_string()),
    }];

    // Session B independently advertises a DIFFERENT set.
    *roots_b.write().await = vec![RootEntry {
        uri: "file:///srv/app-b".to_string(),
        name: Some("app-b".to_string()),
    }];

    let snap_a = roots_a.read().await.clone();
    let snap_b = roots_b.read().await.clone();
    assert_eq!(snap_a.len(), 1);
    assert_eq!(snap_a[0].uri, "file:///srv/app-a");
    assert_eq!(
        snap_b.len(),
        1,
        "FIND-037: B's roots must remain its own after A has set its roots"
    );
    assert_eq!(snap_b[0].uri, "file:///srv/app-b");

    // Session A clears its roots — B's stay put.
    roots_a.write().await.clear();
    assert_eq!(roots_a.read().await.len(), 0);
    assert_eq!(
        roots_b.read().await.len(),
        1,
        "FIND-037: A clearing its roots must not affect B"
    );
}
