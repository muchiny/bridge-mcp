#![no_main]

use std::sync::LazyLock;

use bridge_mcp::Sanitizer;
use bridge_mcp::security::ANSI_PATTERN;
use libfuzzer_sys::fuzz_target;

// Create sanitizer ONCE at startup, reuse for all fuzz inputs
static SANITIZER: LazyLock<Sanitizer> = LazyLock::new(Sanitizer::with_defaults);

// The sanitizer's own ANSI pattern, taken from the code under test rather
// than restated here, so the guard below cannot drift from what actually
// gets removed.
static ANSI_ESCAPE_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(ANSI_PATTERN).expect("the sanitizer's own pattern compiles")
});

fuzz_target!(|data: &str| {
    // Fuzz the sanitize function (using pre-compiled regex patterns)
    let result = SANITIZER.sanitize(data);

    // Invariants that must always hold:
    // 1. Content that survives stripping must survive sanitizing.
    //
    // The guard has to mirror what the sanitizer removes, not merely skip
    // control characters. `\x1b[31m` is four non-control characters riding on
    // one ESC; the sanitizer drops the whole sequence, correctly, and the old
    // guard called that a crash. It filed a nightly issue from 2026-08-20 to
    // 2026-09-08 and every one of them was this.
    let stripped = ANSI_ESCAPE_REGEX.replace_all(data, "");
    if stripped.chars().any(|c| !c.is_control() && c != '\u{fffd}') {
        assert!(
            !result.is_empty(),
            "Sanitizer emptied an input that had printable content \
             outside its escape sequences: {data:?}"
        );
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
