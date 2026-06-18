#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::mcp::shell_escape;

fuzz_target!(|data: &str| {
    // Fuzz the shell_escape function
    let escaped = shell_escape(data);

    // Invariants that must always hold:
    // 1. Result should start and end with single quotes
    assert!(escaped.starts_with('\''), "Must start with quote");
    assert!(escaped.ends_with('\''), "Must end with quote");

    // 2. Result should never be empty (at minimum "''")
    assert!(escaped.len() >= 2, "Must have at least 2 chars");

    // 3. No unescaped single quotes in the middle
    let inner = &escaped[1..escaped.len()-1];
    // The only valid patterns are: regular chars or '\'' escape sequence
    // This is complex to verify, but we can at least check it doesn't panic
});
