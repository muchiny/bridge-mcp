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

    // The sequence, refused by the TYPE and not merely by the guard.
    //
    // `parse_incoming` refuses an array textually and always has, so
    // `raw.is_err()` says nothing about `JsonRpcMessage` itself — which is
    // why this needs its own line. It is the `from_str` door, the one the
    // textual guard short-circuits before serde ever sees the bytes; the
    // `from_value` door is covered by the assertion just below, since on an
    // array `raw` is always an error and `via_value` must therefore be `None`.
    if data.trim_start().starts_with('[') {
        assert!(
            serde_json::from_str::<JsonRpcMessage>(data).is_err(),
            "a JSON sequence filled JsonRpcMessage — the positional tool call \
             is back, and only `parse_incoming`'s textual guard is refusing \
             it: {data:?}"
        );
    }

    // No SHAPE is exempt any more. This assertion used to carry an
    // `is_object` derogation, because on an ARRAY the two paths differed by
    // design: `parse_incoming` refused one textually, while the DERIVED
    // `Deserialize` for `JsonRpcMessage` filled the struct positionally —
    // `["2.0",1,"tools/call",{"name":"ssh_exec",…}]` became a complete,
    // dispatchable tool call, and the textual guard was the only thing
    // between it and dispatch. `JsonRpcMessage` refuses a sequence at the
    // level of the type now (`ObjectOnly` in `src/mcp/protocol.rs`), so the
    // shape derogation would excuse a divergence that no longer exists — and
    // an exemption left behind after its reason is gone is how the next one
    // slips in unnoticed.
    //
    // One REASON stays exempt, and this is the fourth oracle in this project
    // to have been wrong rather than the code. The blanket form asserted a
    // property `serde_json::Value` does not have: a `Map` holds one value per
    // name, so a duplicate member is already GONE by the time the bytes are a
    // `Value`, and no deserializer downstream can refuse what it cannot see.
    // The target was therefore RED on healthy code — reproduced on `main`,
    // from `fuzz/seeds/fuzz_jsonrpc_parse/seed2`, which is that exact input.
    // Nightly-only scheduling is the reason nobody had seen it.
    //
    // So the exemption is named by its reason and not by its shape, and it
    // asserts something on the way through: when the two paths disagree, a
    // duplicate member must be the WHOLE explanation. Any other refusal the
    // `Value` path talks its way out of is the #171 divergence again — stdio
    // answering -32700 while another door dispatches `tools/call`, so a proxy,
    // an audit log or a policy layer reading the first member disagrees with
    // what the server ran. The literal `duplicate field` is pinned here, in
    // `src/mcp/transport/http.rs` and in `src/mcp/protocol.rs`: three places,
    // one string, on purpose.
    if let Err(e) = &raw {
        assert!(
            via_value.is_none() || e.message.contains("duplicate field"),
            "the Value path ACCEPTED bytes the raw parser refused for a reason \
             a `Value` CAN carry — that is a message two doors of this server \
             would read differently.\n  input: {data:?}\n  raw said: {e:?}\n  \
             via Value: {via_value:?}"
        );
        return;
    }

    // And the mirror: the raw parser accepted, so the `Value` path must too.
    // A `Value` is strictly less informative than the bytes (it is where the
    // duplicate disappears), never more, so there is nothing it can legally
    // refuse that `from_str` allowed. If this ever fires it is the array bug's
    // own mechanism resurfacing — `Value`'s `deserialize_struct` and
    // `deserialize_map` are different functions with different opinions about
    // sequences, and a type reached through both must not have two answers.
    assert!(
        via_value.is_some(),
        "the raw parser accepted a message the Value path refused: {data:?}"
    );

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
