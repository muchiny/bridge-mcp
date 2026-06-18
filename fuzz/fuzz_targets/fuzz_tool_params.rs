#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::ToolCallParams;

fuzz_target!(|data: &[u8]| {
    // Fuzz MCP tool call params parsing
    // This simulates malformed client requests

    let _result: Result<ToolCallParams, _> = serde_json::from_slice(data);

    // Also try as UTF-8 string
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _result: Result<ToolCallParams, _> = serde_json::from_str(json_str);
    }

    // Should never panic, only return Ok/Err
});
