#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::{CommandValidator, SecurityConfig};

fuzz_target!(|pattern: &str| {
    // Test regex pattern compilation and matching
    // This helps detect ReDoS vulnerabilities

    let config = SecurityConfig {
        whitelist: vec![pattern.to_string()],
        blacklist: vec![],
        ..Default::default()
    };

    // Creating the validator compiles the regex
    let validator = CommandValidator::new(&config);

    // Try to validate a simple command
    // This exercises the regex matching
    let _ = validator.validate("echo test");

    // Function should never panic or hang indefinitely
});
