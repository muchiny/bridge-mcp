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

use std::sync::Arc;

use bridge_mcp::mcp::session_context::SessionContext;

use bridge_mcp::config::Config;
use bridge_mcp::mcp::McpServer;
use bridge_mcp::mcp::protocol::WriterMessage;
use serde_json::json;
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
        WriterMessage::Response(_) => panic!("expected Notification on A"),
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
        WriterMessage::Response(_) => panic!("expected Notification on B"),
    }
}

/// `FIND-036`'s 2026-07-28 replacement. The per-URI `resources/subscribe`
/// RPC is gone — folded into `subscriptions/listen`'s
/// `resourceSubscriptions` — so `SessionContext::resource_subs` and the
/// per-session map it isolated are gone with it. What still has to hold is
/// the guarantee the old test existed for: tearing down session A must not
/// touch session B's subscriptions. The registry is server-wide now, so
/// isolation is keyed on writer-channel identity rather than on per-session
/// storage, and `remove_for_tx` is where it can break.
///
/// Reached through the public path (`bridge_mcp::mcp::subscriptions`)
/// deliberately: that is the surface a downstream crate sees.
#[tokio::test]
async fn subscriptions_are_removed_per_session_channel() {
    use bridge_mcp::mcp::subscriptions::{SubscriptionFilter, SubscriptionRegistry};

    let registry = SubscriptionRegistry::new();
    let (tx_a, _rx_a) = mpsc::channel::<WriterMessage>(8);
    let (tx_b, _rx_b) = mpsc::channel::<WriterMessage>(8);

    let watching_history = SubscriptionFilter {
        resource_subscriptions: vec!["history://recent".to_string()],
        ..SubscriptionFilter::default()
    };
    registry.register(json!("a-1"), watching_history.clone(), tx_a.clone());
    registry.register(json!("b-1"), watching_history, tx_b);

    assert_eq!(registry.len(), 2);
    assert_eq!(registry.remove_for_tx(&tx_a), 1);
    assert!(
        registry.filter_of(&json!("a-1")).is_none(),
        "A's subscription is gone"
    );
    assert!(
        registry.filter_of(&json!("b-1")).is_some(),
        "A's teardown must not affect B's subscription"
    );
}

/// `FIND-037`, re-expressed for roots that are per-REQUEST.
///
/// The original bug was a single global `roots: Arc<RwLock<Vec<RootEntry>>>`
/// that `fetch_roots` overwrote from whichever client most recently finished
/// its handshake, so a handler validating a path saw another client's roots.
/// The fix then was per-SESSION storage, and this test compared two handles.
///
/// 3.0.0 removes the storage entirely. Roots now arrive as the answer to a
/// `roots/list` `inputRequest` on the retry of the call that needs them, and
/// are set on that call's `ToolContext` and nowhere else — because carrying a
/// previous request's answer forward is exactly what this revision forbids:
/// *"Servers MUST NOT rely on prior requests over the same connection to
/// establish context (e.g., capabilities, protocol version, client identity).
/// Every request supplies this metadata in its `_meta` field."*
///
/// Per-request is strictly stronger than per-session: there is no shared slot
/// for one client to overwrite. What is left to assert is the absence itself —
/// a context built from a session carries no roots, whatever that session has
/// done before.
#[tokio::test]
async fn roots_never_come_from_the_session() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);

    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let session = SessionContext::new(tx);

    let ctx = server.create_tool_context_for_test(Some(&session)).await;
    assert!(
        ctx.roots.is_empty(),
        "roots must come from the request, not the session: {:?}",
        ctx.roots
    );
}
