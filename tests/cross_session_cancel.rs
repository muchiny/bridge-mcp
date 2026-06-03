//! FIND-038 — verify two clients on the same daemon do NOT share their
//! active-requests map. Regression test for the cross-session
//! cancellation attack documented in the audit 2026-05-09.
//!
//! Threat model: client B sends `notifications/cancelled { requestId }`
//! pointing at a JSON-RPC id that belongs to an in-flight request on
//! client A. Before the fix, the lookup hit a server-wide `HashMap`
//! keyed on the JSON-RPC id alone, so the cancel succeeded and torpedoed
//! A's request. After the fix, each session owns an `ActiveRequests`
//! and the cancel notification is dispatched against the originating
//! session's map only — B's notification finds nothing.
//!
//! This test exercises the same load-bearing data structure
//! (`ActiveRequests`) that the runtime uses inside `serve_session()`.
//! No two-session transport harness exists in this crate; the harness
//! work is intentionally out of scope. The unit test
//! `test_cancel_does_not_cross_sessions` in `src/mcp/server.rs` covers
//! the same property at the module-private level.

use bridge_mcp::config::Config;
use bridge_mcp::mcp::McpServer;

#[tokio::test]
async fn active_requests_are_isolated_across_sessions() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = std::sync::Arc::new(server);

    // Each session must get its OWN ActiveRequests handle. Two calls
    // to the test helper return independent instances — same pattern as
    // PendingRequests / SessionCapabilities (Vuln 8 / Vuln 9).
    let active_a = server.allocate_session_active_requests_for_test();
    let active_b = server.allocate_session_active_requests_for_test();

    // Session A registers a long-running request id "42".
    let token_a = active_a.register("42".to_string());
    assert!(!token_a.is_cancelled(), "fresh token must not be cancelled");

    // Session B has no entry for "42" — even if a malicious client
    // fires `notifications/cancelled { requestId: "42" }` against B's
    // session-local map, the cancel finds nothing.
    assert!(
        !active_b.cancel("42"),
        "session B must not be able to cancel session A's request via B's map"
    );

    // Session A's token is untouched.
    assert!(
        !token_a.is_cancelled(),
        "session B's cancel must not propagate into session A"
    );

    // And session A can still cancel its own request.
    assert!(
        active_a.cancel("42"),
        "session A's own cancellation path still works"
    );
    assert!(
        token_a.is_cancelled(),
        "session A's token fires after A cancels"
    );
}

#[tokio::test]
async fn cross_session_cancel_with_collision_does_not_leak() {
    // Both sessions independently use the same JSON-RPC id (the spec
    // does not require global uniqueness — ids are scoped to the
    // connection). The fix must keep the two cancellations isolated.
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = std::sync::Arc::new(server);

    let active_a = server.allocate_session_active_requests_for_test();
    let active_b = server.allocate_session_active_requests_for_test();

    let token_a = active_a.register("1".to_string());
    let token_b = active_b.register("1".to_string());

    // B cancels its OWN id "1" — that fires B's token.
    assert!(active_b.cancel("1"));
    assert!(token_b.is_cancelled(), "B cancels its own request");

    // A's token must remain untouched.
    assert!(
        !token_a.is_cancelled(),
        "B cancelling its own id must not affect A's token, even on collision"
    );

    // A can still cancel A.
    assert!(active_a.cancel("1"));
    assert!(token_a.is_cancelled());
}
