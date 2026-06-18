#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::database::DatabaseCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz the SQL query validator with arbitrary strings

    let result = DatabaseCommandBuilder::validate_query(data);

    // Invariants:

    // 1. Known dangerous patterns must ALWAYS be rejected (case-insensitive)
    let lower = data.to_lowercase();
    if lower.contains("drop database") {
        assert!(result.is_err(), "DROP DATABASE must be rejected: {data}");
    }
    if lower.contains("drop table") {
        assert!(result.is_err(), "DROP TABLE must be rejected: {data}");
    }
    if lower.contains("truncate") {
        assert!(result.is_err(), "TRUNCATE must be rejected: {data}");
    }
    if lower.contains("delete from") {
        assert!(result.is_err(), "DELETE FROM must be rejected: {data}");
    }

    // 2. Safe queries must ALWAYS be accepted
    // (We can't easily test this with fuzzer input, but we ensure no panics)

    // 3. The function should never panic, regardless of input (implicit)
});
