#![no_main]

use bridge_mcp::ToolCallParams;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};

// The old target called `serde_json::from_slice::<ToolCallParams>` on raw bytes
// and then `from_str` on the same bytes as UTF-8, asserting nothing beyond "did
// not panic". Both doors are wrong for this type, and in different ways.
//
// Wrong door #1: production never parses TEXT into `ToolCallParams`. The
// transport parses the whole message into a `Value` first, and
// `handle_tools_call` calls `serde_json::from_value(params)`
// (`src/mcp/server.rs`, the `let mut call_params: ToolCallParams` binding).
// The two doors DISAGREE: on a duplicate key `from_str` feeds the visitor both
// occurrences and `serde_derive` raises `duplicate field`, while `from_value`
// receives a `serde_json::Map` that already kept only the last. A target
// measuring `from_str` would be measuring a code path this crate does not
// have, and would go red the day someone made the real path stricter.
//
// Wrong door #2: random bytes are not a tool call. Nearly all of them die at
// the first token, so the budget went to proving that `serde_json` rejects
// garbage.
//
// This one BUILDS a `Value` object and asks the question the wire keys exist to
// answer: does each key land in the field it names?
//
// That is not decoration. `ToolCallParams` carries no `rename_all`, so three of
// its five fields answer to a name serde would not derive from the identifier —
// `_meta`, `inputResponses`, `requestState`. The last two are the MRTR
// confirmation pair: `requestState` is the signed token that binds a retry to
// the request the server asked about, and `inputResponses` carries the answers.
// Drop the rename on `request_state` and every retry parses fine, arrives with
// `None`, and reads to the gate as "the client did not confirm" — a
// confirmation loop no client can escape, with no parse error anywhere.
//
// Deliberately NOT asserted: that a `params` ARRAY is refused. `serde_derive`
// generates `visit_seq` for every struct, so `from_value(json!(["ssh_exec"]))`
// does build a `ToolCallParams` — the same positional-filling that #175 had to
// close with a hand-written visitor one level up, at `JsonRpcMessage`. It is
// not reachable here: `RequestMeta::from_params` looks up `_meta` with
// `Value::get`, which answers `None` on an array, so the required-envelope gate
// refuses a positional `params` with `-32602` before `handle_tools_call` runs.
// Asserting a refusal at THIS layer would be asserting something false.

/// Every wire key `ToolCallParams` declares, with the spelling serde would
/// have derived from the field name had the rename been absent.
///
/// The second column is what makes the assertions below two-sided: it is not
/// enough that `requestState` fills `request_state`, because a target that
/// only checked that would stay green if the field answered to BOTH names.
const RENAMED: &[(&str, &str)] = &[
    ("_meta", "meta"),
    ("inputResponses", "input_responses"),
    ("requestState", "request_state"),
];

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Some(head)
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some(flags) = take(&mut rest, 1).map(|b| b[0]) else {
        return;
    };
    let Some(name_len) = take(&mut rest, 1).map(|b| usize::from(b[0])) else {
        return;
    };
    let Some(name_bytes) = take(&mut rest, name_len) else {
        return;
    };
    let (Ok(name), Ok(payload)) = (
        std::str::from_utf8(name_bytes),
        std::str::from_utf8(rest),
    ) else {
        return;
    };

    let write_name = flags & 1 != 0;
    let write_arguments = flags & 2 != 0;
    let write_meta = flags & 4 != 0;
    let write_input_responses = flags & 8 != 0;
    let write_request_state = flags & 16 != 0;
    // The snake_case spellings serde would look for without the renames. When
    // this bit is set they are written INSTEAD of the camelCase ones, and the
    // fields they would fill must stay `None`.
    let write_snake_case = flags & 32 != 0;

    let arguments = json!({ "command": payload });
    let meta = json!({ "progressToken": payload });
    let mut input_responses = Map::new();
    input_responses.insert(payload.to_string(), json!("yes"));

    let mut object = Map::new();
    if write_name {
        object.insert("name".into(), json!(name));
    }
    if write_arguments {
        object.insert("arguments".into(), arguments.clone());
    }
    if !write_snake_case {
        if write_meta {
            object.insert("_meta".into(), meta.clone());
        }
        if write_input_responses {
            object.insert(
                "inputResponses".into(),
                Value::Object(input_responses.clone()),
            );
        }
        if write_request_state {
            object.insert("requestState".into(), json!(payload));
        }
    }
    if write_snake_case {
        // The renamed keys under the names serde would have derived. A field
        // that accepts one of these is a field whose rename stopped being
        // authoritative.
        for (_, derived) in RENAMED {
            object.insert((*derived).into(), json!(payload));
        }
    }

    let document = Value::Object(object);
    let parsed: ToolCallParams = match serde_json::from_value(document.clone()) {
        Ok(p) => p,
        Err(e) => {
            // `name` is the one field with no `#[serde(default)]`, so its
            // absence is the ONLY legitimate reason to refuse this object:
            // everything else here is an `Option` serde fills with `None`.
            //
            // Except one shape the fuzzer will find and which is not a defect:
            // `_meta` deserializes into `ToolCallMeta`, whose
            // `io.modelcontextprotocol/loggingLevel` is a `LogLevel` enum. This
            // target never writes that key, but `progressToken` is a free-form
            // `Value` and cannot fail — so in practice only a missing `name`
            // gets here. Assert exactly that, and name the document, so a
            // future field that quietly stops defaulting shows up as this
            // panic rather than as a silent drop in coverage.
            assert!(
                !write_name,
                "every field but `name` defaults, so a params object carrying \
                 `name` must parse; document: {document}, error: {e}"
            );
            return;
        }
    };
    assert!(
        write_name,
        "`name` has no default, so an object without it must NOT parse; \
         document: {document}"
    );

    // --------------------------------------------------------- the mapping

    assert_eq!(
        parsed.name, name,
        "`name` did not arrive as itself: {document}"
    );

    assert_eq!(
        parsed.arguments,
        write_arguments.then(|| arguments.clone()),
        "`arguments` is the tool's entire input; it must arrive verbatim or \
         not at all: {document}"
    );

    if write_snake_case {
        // The renamed three, under the spellings they must NOT answer to. A
        // rename that disappears makes one of these `Some`, and the retry it
        // governs starts reading a key the reference client never sends.
        assert!(
            parsed.meta.is_none(),
            "`_meta` answered to the derived name `meta`: {document}"
        );
        assert!(
            parsed.input_responses.is_none(),
            "`inputResponses` answered to the derived name `input_responses`; \
             a client's confirmation would be read from a key nothing sends: \
             {document}"
        );
        assert!(
            parsed.request_state.is_none(),
            "`requestState` answered to the derived name `request_state`; the \
             MRTR token binding a retry to its request would be read from a key \
             nothing sends: {document}"
        );
        return;
    }

    assert_eq!(
        parsed.meta.and_then(|m| m.progress_token),
        write_meta.then(|| json!(payload)),
        "`_meta.progressToken` did not arrive as itself: {document}"
    );
    assert_eq!(
        parsed.input_responses,
        write_input_responses.then(|| input_responses.clone()),
        "`inputResponses` carries the client's answers to a confirmation \
         prompt; it must arrive verbatim or not at all: {document}"
    );
    assert_eq!(
        parsed.request_state.as_deref(),
        write_request_state.then_some(payload),
        "`requestState` is the signed token that binds a retry to the request \
         the server asked about. Read from the wrong key it is always absent, \
         which the gate reads as `the client did not confirm` — a confirmation \
         loop with no parse error to explain it: {document}"
    );
});
