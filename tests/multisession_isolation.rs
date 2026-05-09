//! Verify two clients on the same daemon do not share pending-request
//! state. Regression test for Vuln 8 (audit 2026-05-09).

use mcp_ssh_bridge::config::Config;
use mcp_ssh_bridge::mcp::McpServer;
use mcp_ssh_bridge::mcp::pending_requests::ClientResponse;

#[tokio::test]
async fn pending_requests_are_isolated_across_sessions() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = std::sync::Arc::new(server);

    // The server exposes a per-session PendingRequests handle for tests.
    let pr_a = server.allocate_session_pending_for_test();
    let pr_b = server.allocate_session_pending_for_test();

    assert!(
        !std::sync::Arc::ptr_eq(&pr_a, &pr_b),
        "each session must own its own PendingRequests"
    );

    let (id_a, _rx_a) = pr_a.create_request();
    assert!(
        !pr_b.resolve(&id_a, ClientResponse::Success(serde_json::json!("hijack"))),
        "session B must not be able to resolve session A's request"
    );
    assert!(
        pr_a.resolve(&id_a, ClientResponse::Success(serde_json::json!("ok"))),
        "session A's own resolver still works"
    );
}

#[tokio::test]
async fn elicitation_capability_does_not_leak_across_sessions() {
    let config = mcp_ssh_bridge::config::Config::default();
    let (server, _audit_task) = mcp_ssh_bridge::mcp::McpServer::new(config);
    let server = std::sync::Arc::new(server);

    let caps_a = server.allocate_session_capabilities_for_test();
    let caps_b = server.allocate_session_capabilities_for_test();

    assert!(
        !std::sync::Arc::ptr_eq(&caps_a, &caps_b),
        "each session must own its own SessionCapabilities"
    );

    caps_a.set_supports_elicitation(true);
    caps_a.set_supports_sampling(true);
    caps_a.set_supports_roots(true);

    assert!(caps_a.supports_elicitation());
    assert!(
        !caps_b.supports_elicitation(),
        "B must NOT inherit A's elicitation flag"
    );
    assert!(
        !caps_b.supports_sampling(),
        "B must NOT inherit A's sampling flag"
    );
    assert!(
        !caps_b.supports_roots(),
        "B must NOT inherit A's roots flag"
    );
}
