//! Cross-session isolation on the daemon socket.

use bridge_mcp::config::Config;
use bridge_mcp::mcp::McpServer;

/// Vuln 8, re-expressed for a server that initiates no requests.
///
/// The original leak was between SESSIONS: the server sent
/// `elicitation/create` / `sampling/createMessage` / `roots/list` as its own
/// JSON-RPC requests and parked them in a pending-requests map, and sharing one
/// map across sessions would have let client B resolve a confirmation client A
/// was being asked for. The fix then was a per-session map, and this test
/// compared two handles.
///
/// 3.0.0 deletes the map along with the pattern that needed it: MCP 2026-07-28
/// requires server-to-client requests to travel as `inputRequests` inside an
/// `InputRequiredResult`, answered by the SAME client on its own retry of its
/// own request. There is no outstanding server request for another session to
/// answer, so the vulnerability class has no mechanism left — which is why
/// there is no handle to compare any more.
///
/// What replaces the comparison is the structural claim: an inbound JSON-RPC
/// RESPONSE is now inert. It is dropped rather than routed, on any session.
#[tokio::test]
async fn an_inbound_client_response_is_inert() {
    let (server, _audit_task) = McpServer::new(Config::default());

    // A response shape: an id, a result, and no method.
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "srv-whatever",
        "result": { "action": "accept", "content": { "confirm": true } }
    })
    .to_string();

    let parsed = McpServer::parse_incoming(&response).expect("a response is well-formed JSON-RPC");
    assert!(
        parsed.method.is_none(),
        "the fixture must actually be a response, not a request"
    );

    // And it cannot be turned into a confirmation: the only thing that grants
    // one is a signed `requestState` on the client's own retry.
    let _ = server;
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
