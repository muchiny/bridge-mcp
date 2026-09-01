#![no_main]

use bridge_mcp::mcp::shell_escape;
use bridge_mcp_fuzz::shell_words;
use libfuzzer_sys::fuzz_target;

// What `shell_escape` owes its callers is not a shape but an outcome: the
// string the caller passed is the string the remote program receives.
//
// The previous version of this target checked the shape — starts and ends with
// a quote, no bare quote in the middle. Those hold for an escape that drops
// characters, doubles them, or truncates at the first NUL, and every builder in
// the crate would still be wrong. So the assertion here reads the escaped text
// back the way a shell would (`shell_words`, an independent parser, not the
// inverse of this function) and demands the original.
fuzz_target!(|data: &str| {
    let escaped = shell_escape(data);

    let Some(words) = shell_words(&escaped) else {
        panic!("escaping {data:?} produced shell syntax rather than one word: {escaped:?}");
    };

    assert_eq!(
        words.len(),
        1,
        "escaping {data:?} produced {} words instead of one: {escaped:?} -> {words:?}",
        words.len()
    );
    assert_eq!(
        words[0], data,
        "escaping {data:?} did not round-trip: {escaped:?} reads back as {:?}",
        words[0]
    );
});
