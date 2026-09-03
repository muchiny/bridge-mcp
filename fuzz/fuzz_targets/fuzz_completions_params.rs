#![no_main]

use std::sync::OnceLock;

use bridge_mcp::domain::yaml::parse_yaml;
use bridge_mcp::mcp::protocol::{JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION};
use bridge_mcp::{Config, McpServer};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

// The old target called `serde_json::from_slice::<CompletionsCompleteParams>`
// on raw bytes and asserted nothing. Two things were wrong with that.
//
// It measured serde. `CompletionsCompleteParams` is a plain derive over two
// nested structs; a target that only parses it is a test of `serde_json`'s
// error handling, and the eight targets deleted in #177 were deleted for
// exactly that.
//
// And it stopped one call short of everything that matters. Parsing those
// params is not what `completion/complete` DOES: it then reads the host list
// out of the live config and answers with names. That answer is the product.
// Autocomplete is where an operator learns what hosts exist, so a filter that
// returns a name the prefix does not match is an inventory disclosure — small,
// but real, and invisible to a parse-only target.
//
// So this one goes through `McpServer::handle_request` with the method string
// production dispatches on, against a config this target owns.
//
// `starts_with` versus `contains` is one character in
// `DefaultCompletionProvider::complete_hosts` and no test in the tree
// distinguishes them: the unit tests use a prefix that matches from position 0
// and a prefix that matches nowhere, and both spellings agree on those two.
// The config below is built so they cannot agree — 149 hosts sharing one
// prefix, so almost any interior substring the fuzzer stumbles on separates
// the two, plus one host whose distinguishing token appears ONLY in the
// middle, so the separating input is in the seeds rather than left to luck.
//
// The server is built once. `McpServer::new` compiles the blacklist, builds
// the tool registry, the prompt registry and the resource registry; doing that
// per iteration would leave the target measuring construction. Audit is
// disabled in the config for a blunter reason: it is enabled by default, its
// default path is the operator's real `audit.log`, and `retain_days` deletes
// archives. A fuzz target must not write there.

/// Number of hosts sharing the `node-` prefix.
///
/// Above 100 on purpose: `MAX_COMPLETIONS` truncates the answer, and the
/// truncation is only observable — and `hasMore` only meaningful — when more
/// than 100 names match.
const NODE_HOSTS: usize = 149;

/// The host whose distinguishing token appears only in the middle.
///
/// `QQ7` is not a prefix of this name nor of any `node-…`, so a prefix of
/// `QQ7` must produce NOTHING. Under `contains` it produces this host.
const MIDDLE_MATCH_HOST: &str = "edge-QQ7-gw";

struct Fixture {
    runtime: tokio::runtime::Runtime,
    server: McpServer,
    /// Every host name in the config, sorted — the answer key for both
    /// membership and ordering.
    hosts: Vec<String>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut hosts = Vec::with_capacity(NODE_HOSTS + 1);
        for i in 0..NODE_HOSTS {
            hosts.push(format!("node-{i:03}"));
        }
        hosts.push(MIDDLE_MATCH_HOST.to_string());
        hosts.sort();

        let entries: Vec<String> = hosts
            .iter()
            .map(|name| {
                format!(
                    "{}:{{\"hostname\":\"{name}.internal\",\"user\":\"u\",\
                       \"auth\":{{\"type\":\"agent\"}}}}",
                    json!(name),
                )
            })
            .collect();
        // JSON, which is valid YAML 1.2, through the same hardened reader the
        // product uses. Written rather than deserialized field by field so the
        // fixture cannot drift from the config schema.
        let document = format!(
            "{{\"hosts\":{{{}}},\"audit\":{{\"enabled\":false}}}}",
            entries.join(",")
        );
        let config: Config = parse_yaml(&document).expect("the fixture config must parse");
        assert_eq!(
            config.hosts.len(),
            hosts.len(),
            "two fixture hosts collided; the answer key would be wrong"
        );

        let (server, _audit_task) = McpServer::new(config);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");
        Fixture {
            runtime,
            server,
            hosts,
        }
    })
}

/// The per-request `_meta` envelope 2026-07-28 marks Required on every
/// client-to-server request.
fn envelope() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn ask(fixture: &Fixture, params: Option<Value>) -> JsonRpcResponse {
    fixture.runtime.block_on(fixture.server.handle_request(JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "completion/complete".to_string(),
        params,
    }))
}

/// The static lists `complete_from_list` serves, by argument name.
const STATIC_LISTS: &[(&str, &[&str])] = &[
    ("scope", &["quick", "standard", "thorough"]),
    ("environment", &["dev", "staging", "production"]),
    (
        "issue",
        &["high-cpu", "disk-full", "network", "memory", "service-down"],
    ),
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, prefix_bytes)) = data.split_first() else {
        return;
    };
    let Ok(prefix) = std::str::from_utf8(prefix_bytes) else {
        return;
    };
    let fixture = fixture();

    // Which argument is being completed. `host` is the one that reads config;
    // the three static lists and one name the provider does not know share the
    // rest of the space so every arm of both `match` blocks is reachable.
    let (arg_name, static_list): (&str, Option<&[&str]>) = match selector % 5 {
        0 | 1 => ("host", None),
        2 => (STATIC_LISTS[0].0, Some(STATIC_LISTS[0].1)),
        3 => (STATIC_LISTS[1].0, Some(STATIC_LISTS[1].1)),
        _ => (STATIC_LISTS[2].0, Some(STATIC_LISTS[2].1)),
    };
    // Resources know only `host`; prompts know all four.
    let by_resource = selector & 0x80 != 0;
    let reference = if by_resource {
        json!({ "type": "ref/resource", "uri": "metrics://prod" })
    } else {
        json!({ "type": "ref/prompt", "name": "system-health" })
    };
    let body = json!({
        "ref": reference,
        "argument": { "name": arg_name, "value": prefix }
    });

    // -------------------------------------------------- the envelope is required

    // Same params, no `_meta`. 2026-07-28 makes a request missing a required
    // envelope field MALFORMED, which is `-32602` and not a silently empty
    // completion list — a client that gets an empty list reads "no such host".
    let bare = ask(fixture, Some(body.clone()));
    let error = bare
        .error
        .unwrap_or_else(|| panic!("a request with no `_meta` envelope must be refused: {body}"));
    assert_eq!(
        error.code, -32602,
        "an absent envelope is a malformed request, not a capability problem: \
         {body}"
    );

    // ------------------------------------------------------------- the answer

    let mut params = body.clone();
    params["_meta"] = envelope();
    let response = ask(fixture, Some(params.clone()));
    assert!(
        response.error.is_none(),
        "a well-formed completion request must not error: {params}, got {:?}",
        response.error
    );
    let result = response
        .result
        .unwrap_or_else(|| panic!("a response with no error must carry a result: {params}"));
    let completion = &result["completion"];
    let values: Vec<&str> = completion["values"]
        .as_array()
        .unwrap_or_else(|| panic!("`completion.values` must be an array: {result}"))
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("every completion value is a string: {result}"))
        })
        .collect();

    // Whatever the argument, every value offered must be one the prefix
    // actually selects. This is the assertion `starts_with` versus `contains`
    // turns on.
    for value in &values {
        assert!(
            value.starts_with(prefix),
            "the completion {value:?} does not start with the prefix \
             {prefix:?}. A completion list filtered by substring hands back \
             names the client never typed towards — for `host`, that is the \
             config's inventory: {result}"
        );
    }

    if let Some(list) = static_list {
        // A static list is answered even to a `ref/resource`? No: resources
        // know only `host`, so the answer there is empty, and that difference
        // is itself the assertion.
        let expected: Vec<&str> = if by_resource {
            Vec::new()
        } else {
            list.iter()
                .copied()
                .filter(|v| v.starts_with(prefix))
                .collect()
        };
        assert_eq!(
            values, expected,
            "a static completion list is served in declaration order, filtered \
             by prefix, and only to the reference kinds that declare the \
             argument: {result}"
        );
        return;
    }

    // ----------------------------------------------------------- host completion

    let matching: Vec<&str> = fixture
        .hosts
        .iter()
        .map(String::as_str)
        .filter(|h| h.starts_with(prefix))
        .collect();

    for value in &values {
        assert!(
            fixture.hosts.iter().any(|h| h == value),
            "the completion {value:?} is not a host in the config — the \
             provider invented it: {result}"
        );
    }
    assert!(
        values.windows(2).all(|w| w[0] < w[1]),
        "host completions are sorted, and host names are unique, so they are \
         strictly ascending: {result}"
    );
    assert!(
        values.len() <= 100,
        "a completion answer carries at most 100 values: {result}"
    );

    // `hasMore` is what tells the client the list was cut. Absent means it was
    // not — so when it is absent, the list must be COMPLETE. With 150 hosts
    // behind one prefix this is reachable, and it is the only thing standing
    // between an operator and "these are all the hosts there are".
    let has_more = completion["hasMore"].as_bool().unwrap_or(false);
    if has_more {
        assert!(
            matching.len() > values.len(),
            "`hasMore` claims values were withheld, but the prefix {prefix:?} \
             matches {} hosts and {} were returned: {result}",
            matching.len(),
            values.len()
        );
    } else {
        assert_eq!(
            values.len(),
            matching.len(),
            "`hasMore` is absent, so this is the whole answer — yet the prefix \
             {prefix:?} matches {} hosts in the config and only {} came back: \
             {result}",
            matching.len(),
            values.len()
        );
        assert!(
            values == matching,
            "a complete, sorted answer must be exactly the matching hosts in \
             order: {result}"
        );
    }

    // `total` is the count the client shows next to the list.
    let total = completion["total"]
        .as_u64()
        .unwrap_or_else(|| panic!("`completion.total` must be a number: {result}"));
    assert_eq!(
        usize::try_from(total).unwrap_or(usize::MAX),
        matching.len(),
        "`total` must be how many completions exist for the prefix {prefix:?}, \
         not how many fit in the page: {result}"
    );
});
