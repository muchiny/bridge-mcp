//! Verify two clients on the same daemon do not share pending-request
//! state. Regression test for Vuln 8 (audit 2026-05-09).

use bridge_mcp::config::Config;
use bridge_mcp::mcp::McpServer;
use bridge_mcp::mcp::pending_requests::ClientResponse;

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

/// Vuln 9, re-expressed for a server with no handshake.
///
/// The original leak was between SESSIONS: `initialize` wrote capability
/// flags into a per-session `SessionCapabilities`, and sharing one handle
/// across sessions would have let client A's declaration grant rights to
/// client B. 3.0.0 deleted the type — capabilities are declared per REQUEST,
/// in `_meta` — so the old test has no handle left to compare.
///
/// The guarantee did not shrink with the type, it GREW, and this asserts the
/// larger one. The unit of isolation went from the session to the request, so
/// there are now three ways a declaration could leak instead of one: into
/// another session, into the declaring session itself, and into a sibling
/// request of that same session. All three are checked. The middle one is the
/// case that did not exist before `with_request_meta`, and it is the one a
/// naive implementation (mutating the bundle in place instead of cloning it)
/// would get wrong.
#[tokio::test]
async fn a_declared_capability_does_not_leak_beyond_its_own_request() {
    use bridge_mcp::mcp::protocol::WriterMessage;
    use bridge_mcp::mcp::request_meta::RequestMeta;
    use bridge_mcp::mcp::session_context::SessionContext;

    fn session() -> SessionContext {
        let (tx, _rx) = tokio::sync::mpsc::channel::<WriterMessage>(8);
        SessionContext::new(tx)
    }

    let declaring = serde_json::json!({
        "_meta": {
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": {}, "sampling": {}, "roots": {}
            }
        }
    });

    let session_a = session();
    let session_b = session();

    let request_a = session_a.with_request_meta(RequestMeta::from_params(Some(&declaring)));
    assert!(
        request_a.supports_elicitation(),
        "the declaring request must get what it declared"
    );

    // 1. Not into another session.
    assert!(
        !session_b.supports_elicitation(),
        "session B must not inherit session A's request-level declaration"
    );

    // 2. Not into its OWN session. `with_request_meta` clones; if it mutated,
    //    every later request of this session would inherit the grant.
    assert!(
        !session_a.supports_elicitation(),
        "the declaration must not persist into the session it came from"
    );
    assert!(!session_a.supports_sampling());
    assert!(!session_a.supports_roots());

    // 3. Not into a sibling request of the same session. This is the case
    //    Vuln 9 could not have had: two requests, one bundle, concurrent.
    let sibling = session_a.with_request_meta(RequestMeta::from_params(Some(
        &serde_json::json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} } }),
    )));
    assert!(
        !sibling.supports_elicitation(),
        "a sibling request declaring `{{}}` must not inherit its neighbour's grant"
    );
    // And the original is unchanged by the sibling existing.
    assert!(request_a.supports_elicitation());
}
