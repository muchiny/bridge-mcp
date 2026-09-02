#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::database::DatabaseCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz the SQL query validator with arbitrary strings

    let result = DatabaseCommandBuilder::validate_query(data);

    // Invariants:

    // 1. Known dangerous patterns must ALWAYS be rejected (case-insensitive)
    //
    // ASCII input only, and that restriction is the assertion's correctness
    // rather than laziness. This oracle models "the keyword stands at a token
    // boundary" with an ASCII rule, while the product's `\b` comes from the
    // `regex` crate and is UNICODE-aware, and its `(?i)` is Unicode simple case
    // folding rather than `str::to_lowercase`. The three disagree on non-ASCII
    // input in both directions: `SELEdRop; DROP TABLE\u{210a}` has an ASCII
    // non-word byte after `TABLE` (the first byte of a multi-byte char) so the
    // ASCII rule calls it a boundary, while `\b` sees a Unicode letter and
    // correctly does not match — the product accepts it, and the assertion
    // called that a defect. Rather than reimplement Unicode word boundaries and
    // case folding here, where a near-miss is exactly the failure this project
    // keeps paying for, the assertions apply where the two models provably
    // agree. SQL keywords are ASCII.
    if !data.is_ascii() {
        return;
    }
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
    // `contains_keyword` here too, and for the reason the comment above already
    // gives. This line was left as a bare `contains` when the `truncate` one was
    // fixed, so it demanded that `-delete fromstn` be refused — but the product
    // regex is `\bDELETE\s+FROM\b`, and `fromstn` is an identifier, not the
    // FROM keyword. Refusing it would be the defect. Found by
    // `fuzz_db_query_validation` once the target had seeds; before them the
    // fuzzer never built a string that split the keyword this way.
    if contains_keyword(&lower, "delete from") {
        assert!(result.is_err(), "DELETE FROM must be rejected: {data}");
    }

    // 2. Safe queries must ALWAYS be accepted
    // (We can't easily test this with fuzzer input, but we ensure no panics)

    // 3. The function should never panic, regardless of input (implicit)
});

/// True when `needle` occurs in `haystack` as a whole token, i.e. not glued to
/// a neighbouring alphanumeric or `_`. Mirrors how the validator scans, so the
/// invariant tests the guarantee the product actually makes.
///
/// ASCII only — see the caller. `haystack` is checked before this runs, so
/// indexing a byte at a boundary cannot land mid-character.
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
