#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::SamplingCreateMessageResult;

// `SamplingCreateMessageResult` is the half of `sampling/createMessage` that
// crosses the trust boundary INBOUND: the server sends the request and the
// client answers with this. A hostile or simply buggy MCP client controls
// every byte of it.
//
// This target used to parse `SamplingCreateMessageParams` instead — the
// outbound request, which is `Serialize` only and which nothing in the server
// ever deserializes. It stopped compiling when `Deserialize` was dropped from
// that type, and nobody noticed for six weeks because the whole fuzz harness
// was silently failing to build.
fuzz_target!(|data: &[u8]| {
    let _: Result<SamplingCreateMessageResult, _> = serde_json::from_slice(data);

    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<SamplingCreateMessageResult, _> = serde_json::from_str(s);
    }
});
