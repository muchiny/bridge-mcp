#![no_main]

use bridge_mcp::mcp::protocol::JsonRpcMessage;
use bridge_mcp::McpServer;
use libfuzzer_sys::fuzz_target;

// The old target deserialised arbitrary bytes and asserted nothing beyond
// "did not panic", with a comment claiming invariants it never checked. A
// JSON-RPC parser that never panics can still let two transports of the same
// server disagree about what a message says — which is what happened.
//
// `McpServer::parse_incoming` deserialises the raw text straight into
// `JsonRpcMessage`, so serde refuses a duplicate member. The HTTP transport
// used to go through `serde_json::Value` first, and a `Value` map silently
// keeps the LAST of two members with the same name. On
// `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call",…}`
// stdio answered -32700 and HTTP dispatched `tools/call`, so anything reading
// the first member — a proxy, an audit log, a policy layer — disagreed with
// what the server ran.
//
// The fix routed HTTP through `parse_incoming` too. This target pins the
// property that makes the fix meaningful, without needing the HTTP stack: the
// Value-mediated path must never be MORE permissive than the raw one.
fuzz_target!(|data: &str| {
    let raw = McpServer::parse_incoming(data);

    // The same bytes, seen through a `Value` first — the shape the HTTP door
    // used to have, and the shape any future caching or logging layer would
    // reintroduce by accident.
    let via_value = serde_json::from_str::<serde_json::Value>(data)
        .ok()
        .and_then(|v| serde_json::from_value::<JsonRpcMessage>(v).ok());

    // Objects only. On an ARRAY the two paths differ by design and not by
    // accident: `parse_incoming` refuses one textually, while the derived
    // `Deserialize` for `JsonRpcMessage` will happily fill the struct
    // positionally — `["2.0",1,"tools/call",{"name":"ssh_exec",…}]` becomes a
    // complete, dispatchable tool call. That textual guard is therefore the
    // only thing between a positional array and dispatch, which is worth
    // knowing and is asserted separately below; folding it in here would make
    // this target red on healthy code, and a red that everyone learns to
    // ignore is worse than no assertion at all.
    let is_object = data.trim_start().starts_with('{');

    if raw.is_err() {
        assert!(
            via_value.is_none() || !is_object,
            "the Value path ACCEPTED an object the raw parser refused — that is a \
             message two doors of this server would read differently.\n  input: {data:?}\n  \
             raw said: {:?}\n  via Value: {:?}",
            raw.as_ref().err(),
            via_value
        );
        return;
    }

    let raw = raw.expect("checked above");

    // Nothing is invented. Every member the parser reports must have been
    // written by the sender: a `default` or an alias quietly filling one in
    // would mean the server acts on a field nobody sent.
    let text: serde_json::Value = serde_json::from_str(data).expect("it parsed as a message");
    let object = text
        .as_object()
        .expect("parse_incoming refuses everything that is not an object");

    assert_eq!(
        raw.method.is_some(),
        object.contains_key("method"),
        "`method` must be present exactly when the sender wrote it: {data:?}"
    );
    assert_eq!(
        raw.params.is_some(),
        object.contains_key("params"),
        "`params` must be present exactly when the sender wrote it: {data:?}"
    );
    assert_eq!(
        raw.id.is_some(),
        object.get("id").is_some_and(|v| !v.is_null()),
        "`id` must be present exactly when the sender wrote a non-null one: {data:?}"
    );
    assert_eq!(
        Some(&serde_json::Value::String(raw.jsonrpc.clone())),
        object.get("jsonrpc"),
        "`jsonrpc` must be exactly what the sender wrote: {data:?}"
    );

    // Batching was removed in revision 2025-06-18 and 2026-07-28 does not
    // bring it back, on ANY transport.
    assert!(
        !data.trim_start().starts_with('['),
        "an array was accepted as a JSON-RPC message: {data:?}"
    );
});
