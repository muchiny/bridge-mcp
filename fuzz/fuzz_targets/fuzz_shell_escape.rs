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

    // 3. No unescaped single quotes in the middle.
    //
    // This used to compute `inner` and then do nothing with it, on the grounds
    // that the check was "complex to verify" — which cost a compiler warning
    // and bought no coverage. It is not complex: POSIX escaping replaces every
    // `'` in the input with the four-character sequence `'\''`, so once those
    // sequences are removed no bare quote may remain. That is the single
    // property the whole escape depends on, and it is worth asserting.
    //
    // Slicing by byte is safe here: both ends are the ASCII quote asserted
    // above, so neither index can land inside a multi-byte character.
    let inner = &escaped[1..escaped.len() - 1];
    for fragment in inner.split("'\\''") {
        assert!(
            !fragment.contains('\''),
            "bare single quote outside an escape sequence: {escaped:?}"
        );
    }
});
