#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::JsonRpcRequest;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as JSON-RPC request
    // This simulates malformed/malicious input from network

    // Attempt to parse as JSON
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Try to deserialize as JsonRpcRequest
        let _result: Result<JsonRpcRequest, _> = serde_json::from_str(json_str);

        // Whether it succeeds or fails, it should never panic
        // (implicit - if we reach here, no panic occurred)
    }

    // Also try direct byte parsing (non-UTF8)
    let _result: Result<JsonRpcRequest, _> = serde_json::from_slice(data);

    // Invariants:
    // 1. Parsing should never panic, only return Ok/Err
    // 2. No memory corruption or undefined behavior
});
