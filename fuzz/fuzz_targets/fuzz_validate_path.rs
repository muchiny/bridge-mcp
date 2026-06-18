#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::mcp::validate_path;

fuzz_target!(|data: &str| {
    // Fuzz the validate_path function
    let result = validate_path(data);

    // Invariants that must always hold:
    // 1. Paths containing ".." must always be rejected
    if data.contains("..") {
        assert!(result.is_err(), "Path with '..' must be rejected: {}", data);
    }

    // 2. Function should never panic, only return Ok or Err
    // (implicit - if we reach here, no panic occurred)
});
