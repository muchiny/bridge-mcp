#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::database::DatabaseType;

fuzz_target!(|data: &str| {
    // Fuzz the DatabaseType parser with arbitrary strings

    let lower = data.to_lowercase();

    // Invariants:

    // 1. Known valid inputs must always succeed
    if lower == "mysql" {
        let dt = DatabaseType::from_str_checked(data).unwrap();
        assert_eq!(dt, DatabaseType::MySQL);
        assert_eq!(dt.default_port(), 3306);
        assert_eq!(dt.default_user(), "root");
        return;
    }

    if lower == "postgresql" || lower == "postgres" || lower == "psql" {
        let dt = DatabaseType::from_str_checked(data).unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
        assert_eq!(dt.default_port(), 5432);
        assert_eq!(dt.default_user(), "postgres");
        return;
    }

    // 2. Unknown inputs must always fail
    let result = DatabaseType::from_str_checked(data);
    assert!(result.is_err(), "Unknown db type must be rejected: {data}");

    // 3. Should never panic (implicit)
});
