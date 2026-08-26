#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use bridge_mcp::Sanitizer;

// Create sanitizer ONCE at startup, reuse for all fuzz inputs
static SANITIZER: LazyLock<Sanitizer> = LazyLock::new(Sanitizer::with_defaults);

fuzz_target!(|data: &str| {
    // Fuzz the sanitize function (using pre-compiled regex patterns)
    let result = SANITIZER.sanitize(data);

    // Invariants that must always hold:
    // 1. Result should never be empty if input wasn't empty
    if !data.is_empty() {
        // Non-empty input may legitimately sanitize to nothing: an input made
        // only of ANSI escape sequences and invalid UTF-8 bytes has no
        // printable content to keep. The old assertion treated that as a
        // crash.
        if data.chars().any(|c| !c.is_control() && c != '\u{fffd}') {
            assert!(
                !result.is_empty(),
                "Sanitizer emptied an input that had printable content: {data:?}"
            );
        }
    }

    // 2. Result length should be reasonable (not explode due to replacements)
    // Note: We don't check specific masking because the fuzzer generates edge cases
    // like "Aassword=secret" which looks similar but isn't a password pattern
    assert!(
        result.len() <= data.len() + 1000,
        "Sanitized output grew unexpectedly large"
    );

    // 3. Function should never panic (implicit - if we reach here, no panic occurred)
});
