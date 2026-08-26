#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::database::DatabaseCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz the SQL query validator with arbitrary strings

    let result = DatabaseCommandBuilder::validate_query(data);

    // Invariants:

    // 1. Known dangerous patterns must ALWAYS be rejected (case-insensitive)
    let lower = data.to_lowercase();
    if contains_keyword(&lower, "drop database") {
        assert!(result.is_err(), "DROP DATABASE must be rejected: {data}");
    }
    if contains_keyword(&lower, "drop table") {
        assert!(result.is_err(), "DROP TABLE must be rejected: {data}");
    }
    // `contains` is the wrong test: the validator matches SQL keywords at
    // token boundaries, so `kortruncate` is correctly accepted while
    // `truncate t` and `SELECT 1; truncate t` are rejected. Asserting bare
    // containment demanded that the validator reject any identifier that
    // merely embeds the word.
    if contains_keyword(&lower, "truncate") {
        assert!(result.is_err(), "TRUNCATE must be rejected: {data}");
    }
    if lower.contains("delete from") {
        assert!(result.is_err(), "DELETE FROM must be rejected: {data}");
    }

    // 2. Safe queries must ALWAYS be accepted
    // (We can't easily test this with fuzzer input, but we ensure no panics)

    // 3. The function should never panic, regardless of input (implicit)
});

/// True when `needle` occurs in `haystack` as a whole token, i.e. not glued to
/// a neighbouring alphanumeric or `_`. Mirrors how the validator scans, so the
/// invariant tests the guarantee the product actually makes.
fn contains_keyword(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    haystack.match_indices(needle).any(|(i, _)| {
        let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
        let end = i + needle.len();
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        before_ok && after_ok
    })
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
