#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::truncate_output;

fuzz_target!(|data: (&str, u16)| {
    let (input, max_chars_raw) = data;
    let max_chars = max_chars_raw as usize;

    // Fuzz the truncate_output function
    let result = truncate_output(input, max_chars);

    // Invariants that must always hold:

    // 1. If max_chars is 0, should return original unchanged
    if max_chars == 0 {
        assert_eq!(
            result, input,
            "max_chars=0 should return original"
        );
    }

    // 2. If input fits within max_chars, should return original unchanged
    if input.len() <= max_chars {
        assert_eq!(
            result, input,
            "Input fits, should return original"
        );
    }

    // 3. Result should be valid UTF-8 (implicit - String guarantees this)
    // 4. Function should never panic on any UTF-8 input
    //    (implicit - if we reach here, no panic occurred)
});
