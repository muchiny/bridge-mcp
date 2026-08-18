#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::ElicitationCreateResult;

// `ElicitationCreateResult` is the half of `elicitation/create` that crosses
// the trust boundary INBOUND: the server asks for confirmation and the client
// answers with this. It is parsed at `src/mcp/elicitation.rs:162`, and its
// `action` field is what the destructive-operation gate reads before deciding
// whether a `destructive_hint: true` tool may run — so a malformed or hostile
// reply landing here has real consequences.
//
// This target used to parse `ElicitationCreateParams` instead — the outbound
// request, which is `Serialize` only and which nothing in the server ever
// deserializes. It stopped compiling when `Deserialize` was dropped from that
// type, and nobody noticed for six weeks because the whole fuzz harness was
// silently failing to build.
fuzz_target!(|data: &[u8]| {
    let _: Result<ElicitationCreateResult, _> = serde_json::from_slice(data);

    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<ElicitationCreateResult, _> = serde_json::from_str(s);
    }
});
